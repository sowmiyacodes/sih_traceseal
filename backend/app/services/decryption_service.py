from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.crypto.hashing import sha3_256_hex
from app.crypto.pq import sign_event, verify_signature
from app.models.database import SessionLocal
from app.models.decryption_event import DecryptionEvent
from app.services.ledger_service import LedgerService
from app.services.recipient_service import RecipientService


class DecryptionService:
    @staticmethod
    def generate_session_id() -> str:
        return f"SES-{secrets.token_hex(4).upper()}"

    @staticmethod
    def create_decryption_event(document_id: str, recipient_id: str, session_id: str, watermark_id: str, document_hash: str, watermarked_hash: str, private_key: str | None = None, nonce: str | None = None, record_version: str = '1.0') -> dict:
        event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = nonce or secrets.token_hex(12)
        canonical = {
            "event_id": event_id,
            "document_id": document_id,
            "recipient_id": recipient_id,
            "session_id": session_id,
            "watermark_id": watermark_id,
            "document_hash": document_hash,
            "watermarked_hash": watermarked_hash,
            "timestamp": timestamp,
            "nonce": nonce,
            "algorithm": "ML-DSA-65",
            "record_version": record_version,
        }
        event_hash = sha3_256_hex(json.dumps(canonical, separators=(",", ":"), sort_keys=True))
        signature = sign_event(private_key or "00" * 32, event_hash.encode('utf-8'))
        recipient = RecipientService.get_recipient(recipient_id)
        public_key_fingerprint = None
        if recipient:
            try:
                public_key = json.loads(recipient['public_key']).get('ml_dsa_public')
                public_key_fingerprint = sha3_256_hex(bytes.fromhex(public_key)) if public_key else None
            except (ValueError, TypeError, json.JSONDecodeError):
                public_key_fingerprint = None
        event = DecryptionEvent(
            event_id=event_id,
            document_id=document_id,
            recipient_id=recipient_id,
            session_id=session_id,
            watermark_id=watermark_id,
            document_hash=document_hash,
            watermarked_hash=watermarked_hash,
            timestamp=timestamp,
            signature=signature,
            signature_algorithm='ML-DSA-65',
            event_hash=event_hash,
            public_key_fingerprint=public_key_fingerprint,
            ledger_block_id=None,
        )
        db: Session = SessionLocal()
        try:
            db.add(event)
            db.commit()
            db.refresh(event)
        finally:
            db.close()
        LedgerService.add_transaction({
            "event_id": event_id,
            "document_id": document_id,
            "recipient_id": recipient_id,
            "session_id": session_id,
            "watermark_id": watermark_id,
            "event_hash": event_hash,
            "signature": signature,
        })
        return {
            "event_id": event_id,
            "document_id": document_id,
            "recipient_id": recipient_id,
            "session_id": session_id,
            "watermark_id": watermark_id,
            "timestamp": timestamp,
            "document_hash": document_hash,
            "watermarked_hash": watermarked_hash,
            "event_hash": event_hash,
            "signature": signature,
            "signature_algorithm": 'ML-DSA-65',
            "public_key_fingerprint": public_key_fingerprint,
        }

    @staticmethod
    def sign_decryption_event(private_key: str, event_hash: str) -> str:
        return sign_event(private_key, event_hash.encode('utf-8'))

    @staticmethod
    def verify_decryption_event(public_key: str, event_hash: str, signature: str) -> bool:
        return verify_signature(public_key, event_hash.encode('utf-8'), signature)

    @staticmethod
    def get_event_by_id(event_id: str) -> dict | None:
        db = SessionLocal()
        try:
            row = db.query(DecryptionEvent).filter(DecryptionEvent.event_id == event_id).first()
            if row is None:
                return None
            return {
                "event_id": row.event_id,
                "document_id": row.document_id,
                "recipient_id": row.recipient_id,
                "session_id": row.session_id,
                "watermark_id": row.watermark_id,
                "document_hash": row.document_hash,
                "watermarked_hash": row.watermarked_hash,
                "timestamp": row.timestamp,
                "signature": row.signature,
                "signature_algorithm": row.signature_algorithm,
                "public_key_fingerprint": row.public_key_fingerprint,
                "event_hash": row.event_hash,
                "ledger_block_id": row.ledger_block_id,
            }
        finally:
            db.close()

    @staticmethod
    def list_events() -> list[dict]:
        db = SessionLocal()
        try:
            return [
                {
                    "event_id": row.event_id,
                    "document_id": row.document_id,
                    "recipient_id": row.recipient_id,
                    "session_id": row.session_id,
                    "watermark_id": row.watermark_id,
                    "timestamp": row.timestamp,
                    "event_hash": row.event_hash,
                    "signature_algorithm": row.signature_algorithm,
                    "public_key_fingerprint": row.public_key_fingerprint,
                }
                for row in db.query(DecryptionEvent).order_by(DecryptionEvent.id).all()
            ]
        finally:
            db.close()

    @staticmethod
    def process_decryption(document_id: str, recipient_id: str, watermarked_hash: str, watermark_id: str) -> dict:
        session_id = DecryptionService.generate_session_id()
        document_hash = sha3_256_hex(document_id)
        event = DecryptionService.create_decryption_event(document_id, recipient_id, session_id, watermark_id, document_hash, watermarked_hash)
        return event
