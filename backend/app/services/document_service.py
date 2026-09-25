from __future__ import annotations

import os
import base64
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.hashing import sha3_256_hex
from app.crypto.key_store import encrypt_private_key_material, decrypt_private_key_material
from app.crypto.pq import encapsulate, decapsulate, register_fallback_kem_keypair
from app.models.database import SessionLocal
from app.models.document import Document
from app.models.recipient_package import RecipientPackage
from app.services.recipient_service import RecipientService


class DocumentService:
    STORAGE_ROOT = Path(__file__).resolve().parents[2] / "storage"
    MAX_UPLOAD_BYTES = 50 * 1024 * 1024
    ALLOWED_UPLOAD_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.txt', '.docx'}

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
        if Path(safe_name).suffix.lower() not in DocumentService.ALLOWED_UPLOAD_EXTENSIONS:
            raise ValueError('Unsupported file type')
        doc_id = f"DOC-{uuid4().hex[:8].upper()}"
        encrypted_dir = DocumentService.STORAGE_ROOT / "encrypted"
        keys_dir = DocumentService.STORAGE_ROOT / "keys"
        encrypted_dir.mkdir(parents=True, exist_ok=True)
        keys_dir.mkdir(parents=True, exist_ok=True)
        plaintext = file_obj.file.read()
        if len(plaintext) > DocumentService.MAX_UPLOAD_BYTES:
            raise ValueError('File exceeds the 50 MB upload limit')
        key = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        target = encrypted_dir / f"{doc_id}__{safe_name}.enc"
        target.write_bytes(nonce + ciphertext)
        (keys_dir / f'{doc_id}.key.enc').write_text(
            encrypt_private_key_material({"document_key": key.hex()}), encoding='utf-8'
        )
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
                "encryption_key_hex": None,
                "multi_recipient": True,
            }
        finally:
            db.close()

    @staticmethod
    def get_document_key(document_id: str) -> str | None:
        key_path = DocumentService.STORAGE_ROOT / 'keys' / f'{document_id}.key.enc'
        if not key_path.exists():
            legacy_path = DocumentService.STORAGE_ROOT / 'keys' / f'{document_id}.key'
            if legacy_path.exists():
                return legacy_path.read_text(encoding='ascii').strip()
            return None
        payload = decrypt_private_key_material(key_path.read_text(encoding='utf-8'))
        return payload['document_key']

    @staticmethod
    def default_permissions() -> dict[str, bool]:
        return {'view': True, 'download': True, 'print': False, 'edit': False, 'reshare': False}

    @staticmethod
    def normalize_permissions(raw: dict | str | None) -> dict[str, bool]:
        default = DocumentService.default_permissions()
        if raw is None:
            return default
        if isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except (TypeError, ValueError, json.JSONDecodeError):
                return default
        else:
            payload = raw
        if not isinstance(payload, dict):
            return default
        normalized = {str(key).lower(): bool(value) for key, value in payload.items()}
        for key in default:
            if key not in normalized:
                normalized[key] = default[key]
        default.update(normalized)
        return default

    @staticmethod
    def parse_permissions(raw: str | None) -> dict[str, bool]:
        return DocumentService.normalize_permissions(raw)

    @staticmethod
    def validate_expiry(expiry_timestamp: str | None) -> str | None:
        if expiry_timestamp in (None, '', 'none', 'unlimited'):
            return None
        value = str(expiry_timestamp).strip()
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError('Expiration must be a valid ISO-8601 timestamp.')
        return parsed.astimezone(timezone.utc).isoformat()

    @staticmethod
    def sanitize_max_downloads(value: int | str | None) -> int | None:
        if value in (None, '', 'unlimited', 'none'):
            return None
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise ValueError('Maximum downloads must be a positive number.')
        if parsed <= 0:
            raise ValueError('Maximum downloads must be a positive number.')
        return parsed

    @staticmethod
    def generate_trace_id(recipient_id: str) -> str:
        alphabet = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789'
        db: Session = SessionLocal()
        try:
            while True:
                candidate = 'TS-' + ''.join(secrets.choice(alphabet) for _ in range(6))
                exists = db.query(RecipientPackage).filter(RecipientPackage.trace_id == candidate).first()
                if exists is None:
                    return candidate
        finally:
            db.close()

    @staticmethod
    def _package_to_dict(package: RecipientPackage) -> dict:
        return {
            'package_id': package.package_id,
            'document_id': package.document_id,
            'recipient_id': package.recipient_id,
            'trace_id': package.trace_id,
            'issue_timestamp': package.issue_timestamp,
            'expiry_timestamp': package.expiry_timestamp,
            'permissions': DocumentService.parse_permissions(package.permissions),
            'max_downloads': package.max_downloads,
            'view_count': package.view_count,
            'download_count': package.download_count,
            'status': package.status,
            'revocation_reason': package.revocation_reason,
            'revoked_by': package.revoked_by,
            'revoked_at': package.revoked_at,
            'last_accessed_at': package.last_accessed_at,
            'kem_algorithm': 'ML-KEM-768',
            'wrapped_key_algorithm': 'AES-256-GCM',
            'created_at': package.created_at.isoformat() if package.created_at else None,
        }

    @staticmethod
    def create_recipient_packages(document_id: str, recipient_ids: list[str], permissions: dict | str | None = None, expiry_timestamp: str | None = None, max_downloads: int | str | None = None) -> list[dict]:
        document = DocumentService.get_document(document_id)
        if document is None:
            raise ValueError('Document not found')
        if not recipient_ids:
            raise ValueError('At least one recipient is required')
        normalized_permissions = DocumentService.normalize_permissions(permissions)
        if not any(normalized_permissions.values()):
            raise ValueError('At least one permission must be enabled on the distribution.')
        expiry_value = DocumentService.validate_expiry(expiry_timestamp)
        max_download_limit = DocumentService.sanitize_max_downloads(max_downloads)
        key_hex = DocumentService.get_document_key(document_id)
        if key_hex is None:
            raise ValueError('Document key is not available')
        document_key = bytes.fromhex(key_hex)
        db: Session = SessionLocal()
        packages: list[dict] = []
        try:
            for recipient_id in dict.fromkeys(recipient_ids):
                recipient = RecipientService.get_recipient(recipient_id)
                if recipient is None or not recipient.get('active'):
                    raise ValueError(f'Active recipient not found: {recipient_id}')
                existing = db.query(RecipientPackage).filter(
                    RecipientPackage.document_id == document_id,
                    RecipientPackage.recipient_id == recipient_id,
                ).first()
                if existing is not None:
                    existing.permissions = json.dumps(normalized_permissions, sort_keys=True)
                    existing.expiry_timestamp = expiry_value
                    existing.max_downloads = max_download_limit
                    existing.status = 'ACTIVE'
                    existing.revocation_reason = None
                    existing.revoked_by = None
                    existing.revoked_at = None
                    package_payload = DocumentService._package_to_dict(existing)
                    package_payload['existing'] = True
                    packages.append(package_payload)
                    continue
                public_keys = json.loads(recipient['public_key'])
                private_keys = RecipientService.get_private_keys(recipient_id)
                if not private_keys or not private_keys.get('ml_kem_private'):
                    raise ValueError(f'Recipient private key is unavailable: {recipient_id}')
                register_fallback_kem_keypair(private_keys['ml_kem_private'], public_keys['ml_kem_public'])
                kem_ciphertext, shared_secret = encapsulate(public_keys['ml_kem_public'])
                wrapping_key = sha3_256_hex(shared_secret + document_id.encode()).encode()[:32]
                wrap_nonce = os.urandom(12)
                wrapped = wrap_nonce + AESGCM(wrapping_key).encrypt(wrap_nonce, document_key, document_id.encode())
                package = RecipientPackage(
                    package_id=f'PKG-{secrets.token_hex(8).upper()}',
                    document_id=document_id,
                    recipient_id=recipient_id,
                    trace_id=DocumentService.generate_trace_id(recipient_id),
                    issue_timestamp=datetime.now(timezone.utc).isoformat(),
                    expiry_timestamp=expiry_value,
                    permissions=json.dumps(normalized_permissions, sort_keys=True),
                    max_downloads=max_download_limit,
                    status='ACTIVE',
                    kem_ciphertext=kem_ciphertext,
                    wrapped_key=base64.b64encode(wrapped).decode('ascii'),
                )
                db.add(package)
                db.flush()
                package_payload = DocumentService._package_to_dict(package)
                package_payload['existing'] = False
                packages.append(package_payload)
            db.commit()
            return packages
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def decrypt_recipient_package(document_id: str, recipient_id: str) -> dict:
        db: Session = SessionLocal()
        try:
            package = db.query(RecipientPackage).filter(
                RecipientPackage.document_id == document_id,
                RecipientPackage.recipient_id == recipient_id,
            ).first()
            if package is None:
                raise ValueError('No recipient package exists for this document and recipient')
            if package.status != 'ACTIVE':
                raise ValueError(f'This distribution is {package.status.lower()} and cannot be used.')
            private_keys = RecipientService.get_private_keys(recipient_id)
            if not private_keys or not private_keys.get('ml_kem_private'):
                raise ValueError('Recipient private key is unavailable')
            recipient = RecipientService.get_recipient(recipient_id)
            if recipient is None:
                raise ValueError('Recipient record is unavailable')
            public_keys = json.loads(recipient['public_key'])
            register_fallback_kem_keypair(private_keys['ml_kem_private'], public_keys['ml_kem_public'])
            shared_secret = decapsulate(private_keys['ml_kem_private'], package.kem_ciphertext)
            wrapping_key = sha3_256_hex(shared_secret + document_id.encode()).encode()[:32]
            wrapped = base64.b64decode(package.wrapped_key)
            nonce, ciphertext = wrapped[:12], wrapped[12:]
            key = AESGCM(wrapping_key).decrypt(nonce, ciphertext, document_id.encode())
            return {'key': key, 'package_id': package.package_id, 'trace_id': package.trace_id}
        finally:
            db.close()

    @staticmethod
    def get_distribution(document_id: str, recipient_id: str) -> dict | None:
        db: Session = SessionLocal()
        try:
            package = db.query(RecipientPackage).filter(
                RecipientPackage.document_id == document_id,
                RecipientPackage.recipient_id == recipient_id,
            ).first()
            return None if package is None else DocumentService._package_to_dict(package)
        finally:
            db.close()

    @staticmethod
    def get_distribution_by_trace_id(trace_id: str) -> dict | None:
        db: Session = SessionLocal()
        try:
            package = db.query(RecipientPackage).filter(RecipientPackage.trace_id == trace_id).first()
            return None if package is None else DocumentService._package_to_dict(package)
        finally:
            db.close()

    @staticmethod
    def can_access_package(document_id: str, recipient_id: str, action: str) -> dict:
        db: Session = SessionLocal()
        try:
            package = db.query(RecipientPackage).filter(
                RecipientPackage.document_id == document_id,
                RecipientPackage.recipient_id == recipient_id,
            ).first()
            if package is None:
                return {'allowed': False, 'reason': 'not_found', 'document_id': document_id, 'recipient_id': recipient_id}
            if package.status == 'REVOKED':
                return {'allowed': False, 'reason': 'revoked', 'document_id': document_id, 'recipient_id': recipient_id, 'trace_id': package.trace_id}
            if package.expiry_timestamp:
                try:
                    expiry = datetime.fromisoformat(package.expiry_timestamp.replace('Z', '+00:00'))
                    if expiry <= datetime.now(timezone.utc):
                        package.status = 'EXPIRED'
                        db.commit()
                        return {'allowed': False, 'reason': 'expired', 'document_id': document_id, 'recipient_id': recipient_id, 'trace_id': package.trace_id}
                except ValueError:
                    pass
            permissions = DocumentService.parse_permissions(package.permissions)
            key = action.lower()
            if key == 'download' and package.max_downloads is not None and package.download_count >= int(package.max_downloads):
                return {'allowed': False, 'reason': 'download_limit_exceeded', 'document_id': document_id, 'recipient_id': recipient_id, 'trace_id': package.trace_id, 'permissions': permissions, 'max_downloads': package.max_downloads, 'download_count': package.download_count}
            allowed = bool(permissions.get(key, False))
            if allowed and key in {'view', 'download'}:
                if key == 'view':
                    package.view_count += 1
                else:
                    package.download_count += 1
                package.last_accessed_at = datetime.now(timezone.utc).isoformat()
                db.commit()
            return {'allowed': allowed, 'reason': None if allowed else 'permission_denied', 'document_id': document_id, 'recipient_id': recipient_id, 'trace_id': package.trace_id, 'permissions': permissions, 'max_downloads': package.max_downloads, 'download_count': package.download_count}
        finally:
            db.close()

    @staticmethod
    def revoke_distribution(document_id: str, recipient_id: str, reason: str = '', revoked_by: str | None = None) -> dict:
        db: Session = SessionLocal()
        try:
            package = db.query(RecipientPackage).filter(
                RecipientPackage.document_id == document_id,
                RecipientPackage.recipient_id == recipient_id,
            ).first()
            if package is None:
                raise ValueError('Distribution not found')
            package.status = 'REVOKED'
            package.revocation_reason = reason or 'Access revoked by administrator'
            package.revoked_by = revoked_by or 'ADMIN'
            package.revoked_at = datetime.now(timezone.utc).isoformat()
            db.commit()
            db.refresh(package)
            return DocumentService._package_to_dict(package)
        finally:
            db.close()

    @staticmethod
    def list_recipient_packages(document_id: str | None = None, recipient_id: str | None = None) -> list[dict]:
        db: Session = SessionLocal()
        try:
            query = db.query(RecipientPackage)
            if document_id:
                query = query.filter(RecipientPackage.document_id == document_id)
            if recipient_id:
                query = query.filter(RecipientPackage.recipient_id == recipient_id)
            return [DocumentService._package_to_dict(p) for p in query.order_by(RecipientPackage.id).all()]
        finally:
            db.close()

    @staticmethod
    def list_documents(recipient_id: str | None = None) -> list[dict]:
        db: Session = SessionLocal()
        try:
            query = db.query(Document)
            if recipient_id:
                document_ids = select(RecipientPackage.document_id).where(RecipientPackage.recipient_id == recipient_id)
                query = query.filter(Document.document_id.in_(document_ids))
            return [
                {
                    "id": d.id,
                    "document_id": d.document_id,
                    "title": d.title or 'Untitled document',
                    "content": d.content or '',
                    "original_filename": d.original_filename,
                    "encrypted_path": d.encrypted_path,
                    "original_hash": d.original_hash,
                    "encryption_algorithm": d.encryption_algorithm,
                    "decrypted_path": str(DocumentService.STORAGE_ROOT / 'decrypted' / f'{Path(d.original_filename).stem}-decrypted{Path(d.original_filename).suffix}'),
                    "watermarked_path": d.watermarked_path,
                    "created_at": d.created_at.isoformat() if d.created_at else None,
                }
                for d in query.order_by(Document.id).all()
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
                "title": d.title or 'Untitled document',
                "content": d.content or '',
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

    @staticmethod
    def delete_document(document_id: str) -> None:
        db: Session = SessionLocal()
        try:
            row = db.query(Document).filter(Document.document_id == document_id).first()
            if row is None:
                raise ValueError('Document not found')
            paths = [row.encrypted_path, row.decrypted_path, row.watermarked_path]
            db.delete(row)
            db.commit()
        finally:
            db.close()
        for raw_path in paths:
            if raw_path:
                Path(raw_path).unlink(missing_ok=True)

    @staticmethod
    @staticmethod
    def create_document(title: str, content: str, original_filename: str | None = None) -> dict:
        safe_title = (title or '').strip() or 'Untitled document'
        safe_name = DocumentService._normalize_name(original_filename or f'{safe_title}.txt')
        doc_id = f"DOC-{uuid4().hex[:8].upper()}"
        db: Session = SessionLocal()
        try:
            row = Document(
                document_id=doc_id,
                title=safe_title,
                content=(content or '').strip() if content is not None else '',
                original_filename=safe_name,
                encrypted_path=None,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            return DocumentService.get_document(doc_id)
        finally:
            db.close()

    @staticmethod
    def update_document(document_id: str, original_filename: str | None = None, title: str | None = None, content: str | None = None) -> dict:
        db: Session = SessionLocal()
        try:
            row = db.query(Document).filter(Document.document_id == document_id).first()
            if row is None:
                raise ValueError('Document not found')
            if original_filename is not None:
                row.original_filename = DocumentService._normalize_name(original_filename)
            if title is not None:
                row.title = (title or '').strip() or 'Untitled document'
            if content is not None:
                row.content = content or ''
            db.commit()
            db.refresh(row)
            return DocumentService.get_document(document_id)
        finally:
            db.close()
