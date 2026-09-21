from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from app.crypto.hashing import sha3_256_hex
from app.models.database import SessionLocal
from app.models.document import Document


class DocumentService:
    STORAGE_ROOT = Path(__file__).resolve().parents[2] / "storage"

    @staticmethod
    def _normalize_name(filename: str) -> str:
        safe_name = os.path.basename(filename)
        if not safe_name or safe_name in {'.', '..'}:
            raise ValueError('Invalid file name')
        return safe_name

    @staticmethod
    def encrypt_document_file(source_path: str | Path, recipient_id: str, key: bytes | str, document_id: str | None = None) -> dict:
        if isinstance(key, str):
            key = bytes.fromhex(key)
        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f'File not found: {source}')
        if len(key) != 32:
            raise ValueError('AES key must be 32 bytes')
        document_id = document_id or f"DOC-{uuid4().hex[:8].upper()}"
        safe_name = DocumentService._normalize_name(source.name)
        encrypted_dir = DocumentService.STORAGE_ROOT / "encrypted"
        decrypted_dir = DocumentService.STORAGE_ROOT / "decrypted"
        encrypted_dir.mkdir(parents=True, exist_ok=True)
        decrypted_dir.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(12)
        plaintext = source.read_bytes()
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        encrypted_target = encrypted_dir / f"{document_id}__{safe_name}.enc"
        encrypted_target.write_bytes(nonce + ciphertext)
        digest = sha3_256_hex(plaintext)
        db: Session = SessionLocal()
        try:
            entry = Document(document_id=document_id, original_filename=safe_name, encrypted_path=str(encrypted_target), original_hash=digest)
            db.add(entry)
            db.commit()
            db.refresh(entry)
        finally:
            db.close()
        return {
            "id": document_id,
            "document_id": document_id,
            "original_filename": safe_name,
            "encrypted_path": str(encrypted_target),
            "original_hash": digest,
            "recipient_id": recipient_id,
            "encryption_algorithm": "AES-256-GCM",
        }

    @staticmethod
    def decrypt_document_file(encrypted_path: str | Path, key: bytes | str, document_id: str | None = None) -> dict:
        if isinstance(key, str):
            key = bytes.fromhex(key)
        encrypted = Path(encrypted_path)
        if not encrypted.exists():
            raise FileNotFoundError(f'Encrypted file not found: {encrypted}')
        if len(key) != 32:
            raise ValueError('AES key must be 32 bytes')
        payload = encrypted.read_bytes()
        nonce, ciphertext = payload[:12], payload[12:]
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        output_dir = DocumentService.STORAGE_ROOT / "decrypted"
        output_dir.mkdir(parents=True, exist_ok=True)
        encoded_name = encrypted.stem.split('__', 1)[1] if '__' in encrypted.stem else f'{encrypted.stem}.bin'
        original_name = Path(encoded_name)
        target_name = f'{original_name.stem}-decrypted{original_name.suffix}'
        target_path = output_dir / target_name
        target_path.write_bytes(plaintext)
        return {
            "document_id": document_id or encrypted.stem,
            "encrypted_path": str(encrypted),
            "plaintext_path": target_path,
            "decrypted_bytes": len(plaintext),
            "sha3_256": sha3_256_hex(plaintext),
        }

    @staticmethod
    def upload_document(file_obj) -> dict:
        original_name = file_obj.filename or "upload.bin"
        safe_name = DocumentService._normalize_name(original_name)
        doc_id = f"DOC-{uuid4().hex[:8].upper()}"
        encrypted_dir = DocumentService.STORAGE_ROOT / "encrypted"
        keys_dir = DocumentService.STORAGE_ROOT / "keys"
        encrypted_dir.mkdir(parents=True, exist_ok=True)
        keys_dir.mkdir(parents=True, exist_ok=True)
        plaintext = file_obj.file.read()
        key = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        target = encrypted_dir / f"{doc_id}__{safe_name}.enc"
        target.write_bytes(nonce + ciphertext)
        (keys_dir / f'{doc_id}.key').write_text(key.hex(), encoding='ascii')
        digest = sha3_256_hex(plaintext)
        db: Session = SessionLocal()
        try:
            entry = Document(document_id=doc_id, original_filename=safe_name, encrypted_path=str(target), original_hash=digest)
            db.add(entry)
            db.commit()
            db.refresh(entry)
            return {
                "id": entry.id,
                "document_id": entry.document_id,
                "original_filename": entry.original_filename,
                "encrypted_path": entry.encrypted_path,
                "original_hash": entry.original_hash,
                "encryption_algorithm": entry.encryption_algorithm,
                "encryption_key_hex": key.hex(),
            }
        finally:
            db.close()

    @staticmethod
    def get_document_key(document_id: str) -> str | None:
        key_path = DocumentService.STORAGE_ROOT / 'keys' / f'{document_id}.key'
        if not key_path.exists():
            return None
        return key_path.read_text(encoding='ascii').strip()

    @staticmethod
    def list_documents() -> list[dict]:
        db: Session = SessionLocal()
        try:
            return [
                {
                    "id": d.id,
                    "document_id": d.document_id,
                    "original_filename": d.original_filename,
                    "encrypted_path": d.encrypted_path,
                    "original_hash": d.original_hash,
                    "encryption_algorithm": d.encryption_algorithm,
                    "decrypted_path": str(DocumentService.STORAGE_ROOT / 'decrypted' / f'{Path(d.original_filename).stem}-decrypted{Path(d.original_filename).suffix}'),
                    "watermarked_path": d.watermarked_path,
                    "created_at": d.created_at.isoformat() if d.created_at else None,
                }
                for d in db.query(Document).order_by(Document.id).all()
            ]
        finally:
            db.close()

    @staticmethod
    def get_document(document_id: str) -> dict | None:
        db: Session = SessionLocal()
        try:
            d = db.query(Document).filter(Document.document_id == document_id).first()
            if d is None:
                return None
            return {
                "id": d.id,
                "document_id": d.document_id,
                "original_filename": d.original_filename,
                "encrypted_path": d.encrypted_path,
                "original_hash": d.original_hash,
                "encryption_algorithm": d.encryption_algorithm,
                "decrypted_path": d.decrypted_path,
                "watermarked_path": d.watermarked_path,
                "created_at": d.created_at.isoformat() if d.created_at else None,
            }
        finally:
            db.close()

    @staticmethod
    def set_watermarked_path(document_id: str, path: str) -> None:
        db: Session = SessionLocal()
        try:
            row = db.query(Document).filter(Document.document_id == document_id).first()
            if row is not None:
                row.watermarked_path = path
                db.commit()
        finally:
            db.close()
