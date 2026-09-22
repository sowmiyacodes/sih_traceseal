from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

import cv2
import fitz
import numpy as np
from PIL import Image
from sqlalchemy.orm import Session

from app.crypto.hashing import sha3_256_hex
from app.models.database import SessionLocal
from app.models.watermark import Watermark


class WatermarkService:
    STORAGE_ROOT = Path(__file__).resolve().parents[2] / 'storage'
    SUPPORTED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg'}
    ALGORITHM = 'DCT'
    MAGIC = b'TSWM1'
    REPEAT = 3
    COEFFICIENTS = (3, 4, 4, 3)
    STRENGTH = 18.0

    @staticmethod
    def _extension(path: str | Path) -> str:
        return Path(path).suffix.lower()

    @classmethod
    def is_supported(cls, path: str | Path) -> bool:
        return cls._extension(path) in cls.SUPPORTED_EXTENSIONS

    @staticmethod
    def generate_watermark_payload(payload: dict[str, Any]) -> str:
        assembled = '|'.join(str(payload.get(key, '')) for key in ('document_id', 'recipient_id', 'session_id', 'nonce', 'timestamp'))
        return f'WM-{sha3_256_hex(assembled)[:16].upper()}'

    @classmethod
    def _encode_payload(cls, watermark_id: str) -> list[int]:
        value = watermark_id.encode('ascii')
        body = cls.MAGIC + bytes([len(value)]) + value
        checksum = hashlib.sha3_256(body).digest()[:4]
        raw = body + checksum
        bits = [(byte >> shift) & 1 for byte in raw for shift in range(7, -1, -1)]
        return [bit for bit in bits for _ in range(cls.REPEAT)]

    @classmethod
    def _decode_payload(cls, bits: list[int]) -> str | None:
        if len(bits) < 8 * (len(cls.MAGIC) + 1 + 4):
            return None
        expanded: list[int] = []
        for index in range(0, len(bits), cls.REPEAT):
            group = bits[index:index + cls.REPEAT]
            if len(group) < cls.REPEAT:
                break
            expanded.append(1 if sum(group) >= 2 else 0)
        raw = bytes(sum(expanded[index + offset] << (7 - offset) for offset in range(8)) for index in range(0, len(expanded) - 7, 8))
        if not raw.startswith(cls.MAGIC) or len(raw) < len(cls.MAGIC) + 1:
            return None
        value_length = raw[len(cls.MAGIC)]
        start = len(cls.MAGIC) + 1
        end = start + value_length
        if len(raw) < end + 4:
            return None
        body = raw[:end]
        if hashlib.sha3_256(body).digest()[:4] != raw[end:end + 4]:
            return None
        value = raw[start:end].decode('ascii', errors='ignore')
        return value if value.startswith('WM-') else None

    @classmethod
    def _image_to_array(cls, image_bytes: bytes) -> tuple[np.ndarray, str]:
        array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(array, cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError('Unable to decode visual document page')
        return image, 'png'

    @classmethod
    def _array_to_image_bytes(cls, image: np.ndarray, fmt: str = 'png') -> bytes:
        success, encoded = cv2.imencode('.jpg' if fmt in {'jpg', 'jpeg'} else '.png', image, [cv2.IMWRITE_JPEG_QUALITY, 97] if fmt in {'jpg', 'jpeg'} else [])
        if not success:
            raise ValueError('Unable to encode watermarked image')
        return encoded.tobytes()

    @classmethod
    def _embed_image(cls, image: np.ndarray, watermark_id: str) -> np.ndarray:
        if image.shape[0] < 80 or image.shape[1] < 80:
            raise ValueError('Visual document is too small for DCT watermarking')
        yuv = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb).astype(np.float32)
        channel = yuv[:, :, 0]
        bits = cls._encode_payload(watermark_id)
        capacity = (channel.shape[0] // 8) * (channel.shape[1] // 8)
        if len(bits) > capacity:
            raise ValueError('Visual document does not have enough DCT capacity')
        bit_index = 0
        for row in range(0, channel.shape[0] - 7, 8):
            for col in range(0, channel.shape[1] - 7, 8):
                if bit_index >= len(bits):
                    break
                block = channel[row:row + 8, col:col + 8]
                dct = cv2.dct(block)
                first_row, first_col, second_row, second_col = cls.COEFFICIENTS
                left = dct[first_row, first_col]
                right = dct[second_row, second_col]
                midpoint = (left + right) / 2.0
                if bits[bit_index] == 1:
                    dct[first_row, first_col] = midpoint + cls.STRENGTH / 2
                    dct[second_row, second_col] = midpoint - cls.STRENGTH / 2
                else:
                    dct[first_row, first_col] = midpoint - cls.STRENGTH / 2
                    dct[second_row, second_col] = midpoint + cls.STRENGTH / 2
                channel[row:row + 8, col:col + 8] = cv2.idct(dct)
                bit_index += 1
            if bit_index >= len(bits):
                break
        yuv[:, :, 0] = np.clip(channel, 0, 255)
        return cv2.cvtColor(yuv.astype(np.uint8), cv2.COLOR_YCrCb2BGR)

    @classmethod
    def _extract_image(cls, image: np.ndarray) -> str | None:
        yuv = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb).astype(np.float32)
        channel = yuv[:, :, 0]
        required_bits = (len(cls.MAGIC) + 1 + 19 + 4) * 8 * cls.REPEAT
        capacity = (channel.shape[0] // 8) * (channel.shape[1] // 8)
        if capacity < required_bits:
            return None
        bits: list[int] = []
        for row in range(0, channel.shape[0] - 7, 8):
            for col in range(0, channel.shape[1] - 7, 8):
                block = channel[row:row + 8, col:col + 8]
                dct = cv2.dct(block)
                first_row, first_col, second_row, second_col = cls.COEFFICIENTS
                bits.append(1 if dct[first_row, first_col] > dct[second_row, second_col] else 0)
                if len(bits) >= required_bits:
                    return cls._decode_payload(bits)
        return None

    @classmethod
    def _render_pdf(cls, path: Path) -> list[np.ndarray]:
        document = fitz.open(str(path))
        try:
            pages = []
            for page in document:
                pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                image = np.frombuffer(pixmap.samples, dtype=np.uint8).reshape(pixmap.height, pixmap.width, pixmap.n)
                pages.append(cv2.cvtColor(image, cv2.COLOR_RGB2BGR))
            return pages
        finally:
            document.close()

    @classmethod
    def _embed_pdf(cls, path: Path, watermark_id: str, output_path: Path) -> int:
        source = fitz.open(str(path))
        output = fitz.open()
        try:
            if source.page_count == 0:
                raise ValueError('PDF contains no pages')
            for page in source:
                pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                image = np.frombuffer(pixmap.samples, dtype=np.uint8).reshape(pixmap.height, pixmap.width, pixmap.n)
                marked = cls._embed_image(cv2.cvtColor(image, cv2.COLOR_RGB2BGR), watermark_id)
                png_bytes = cls._array_to_image_bytes(marked, 'png')
                new_page = output.new_page(width=page.rect.width, height=page.rect.height)
                new_page.show_pdf_page(new_page.rect, source, page.number)
                new_page.insert_image(new_page.rect, stream=png_bytes)
            output.save(str(output_path), garbage=4, deflate=True)
            return len(source)
        finally:
            source.close()
            output.close()

    @classmethod
    def generate_watermark_record(cls, document_id: str, recipient_id: str, session_id: str, nonce: str) -> dict:
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {'document_id': document_id, 'recipient_id': recipient_id, 'session_id': session_id, 'nonce': nonce, 'timestamp': timestamp}
        watermark_id = cls.generate_watermark_payload(payload)
        record = {
            'watermark_id': watermark_id,
            'document_id': document_id,
            'recipient_id': recipient_id,
            'session_id': session_id,
            'nonce': nonce,
            'watermark_hash': sha3_256_hex(json.dumps(payload, sort_keys=True)),
            'algorithm': cls.ALGORITHM,
            'confidence': 1.0,
            'created_at': timestamp,
        }
        db: Session = SessionLocal()
        try:
            existing = db.query(Watermark).filter(Watermark.watermark_id == watermark_id).first()
            if existing is None:
                db.add(Watermark(
                    watermark_id=watermark_id,
                    document_id=document_id,
                    recipient_id=recipient_id,
                    session_id=session_id,
                    nonce=nonce,
                    watermark_hash=record['watermark_hash'],
                    algorithm=cls.ALGORITHM,
                    confidence=1.0,
                ))
                db.commit()
        finally:
            db.close()
        return record

    @classmethod
    def embed_watermark(cls, source_path: str | Path, recipient_id: str, document_id: str, session_id: str, nonce: str) -> dict:
        source = Path(source_path)
        if not cls.is_supported(source):
            raise ValueError('Watermarking requires a PDF, PNG, or JPEG visual document.')
        record = cls.generate_watermark_record(document_id, recipient_id, session_id, nonce)
        output_dir = cls.STORAGE_ROOT / 'watermarked'
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f'{source.stem}-{record["watermark_id"]}{source.suffix.lower()}'
        if source.suffix.lower() == '.pdf':
            pages = cls._embed_pdf(source, record['watermark_id'], output)
        else:
            image, fmt = cls._image_to_array(source.read_bytes())
            output.write_bytes(cls._array_to_image_bytes(cls._embed_image(image, record['watermark_id']), fmt))
            pages = 1
        return {**record, 'success': True, 'output_path': str(output), 'pages': pages, 'algorithm': cls.ALGORITHM}

    @classmethod
    def detect_watermark(cls, document_path: str | Path) -> dict:
        path = Path(document_path)
        base = {'detected': False, 'watermark_id': None, 'confidence': 0.0, 'algorithm': cls.ALGORITHM, 'page': None, 'pages_scanned': 0}
        if not cls.is_supported(path):
            return {**base, 'supported': False, 'message': 'Watermark detection unavailable. This engine requires PDF, PNG, or JPEG.'}
        try:
            if path.suffix.lower() == '.pdf':
                pages = cls._render_pdf(path)
            else:
                pages = [cls._image_to_array(path.read_bytes())[0]]
            for index, image in enumerate(pages, start=1):
                watermark_id = cls._extract_image(image)
                if watermark_id:
                    return {**base, 'supported': True, 'detected': True, 'watermark_id': watermark_id, 'confidence': 0.99, 'page': index, 'pages_scanned': len(pages), 'message': 'TraceSeal watermark detected'}
            return {**base, 'supported': True, 'pages_scanned': len(pages), 'message': 'No TraceSeal watermark detected'}
        except (OSError, ValueError, RuntimeError, fitz.FileDataError) as exc:
            return {**base, 'supported': True, 'message': f'Unable to analyze document: {exc}'}

    @classmethod
    def extract_watermark(cls, document_path: str | Path) -> dict:
        return cls.detect_watermark(document_path)

    @staticmethod
    def list_watermarks() -> list[dict]:
        db = SessionLocal()
        try:
            return [{
                'watermark_id': row.watermark_id,
                'document_id': row.document_id,
                'recipient_id': row.recipient_id,
                'session_id': row.session_id,
                'nonce': row.nonce,
                'watermark_hash': row.watermark_hash,
                'algorithm': row.algorithm,
                'confidence': row.confidence,
                'created_at': row.created_at.isoformat() if row.created_at else None,
            } for row in db.query(Watermark).order_by(Watermark.id).all()]
        finally:
            db.close()

    @staticmethod
    def get_watermark(watermark_id: str) -> dict | None:
        db = SessionLocal()
        try:
            row = db.query(Watermark).filter(Watermark.watermark_id == watermark_id).first()
            if row is None:
                return None
            return {
                'watermark_id': row.watermark_id,
                'document_id': row.document_id,
                'recipient_id': row.recipient_id,
                'session_id': row.session_id,
                'nonce': row.nonce,
                'watermark_hash': row.watermark_hash,
                'algorithm': row.algorithm,
                'confidence': row.confidence,
                'created_at': row.created_at.isoformat() if row.created_at else None,
            }
        finally:
            db.close()
