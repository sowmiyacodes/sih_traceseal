from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.crypto.pq import generate_ml_dsa_keypair, generate_ml_kem_keypair
from app.models.database import SessionLocal
from app.models.recipient import Recipient


class RecipientService:
    @staticmethod
    def create_recipient(name: str, department: str) -> dict:
        db: Session = SessionLocal()
        try:
            recipient_id = f"REC-{len(RecipientService.list_recipients()) + 1:03d}"
            dsa_priv, dsa_pub = generate_ml_dsa_keypair()
            kem_priv, kem_pub = generate_ml_kem_keypair()
            recipient = Recipient(
                recipient_id=recipient_id,
                name=name,
                department=department,
                public_key=json.dumps({"ml_dsa_public": dsa_pub, "ml_kem_public": kem_pub}, sort_keys=True),
                key_algorithm="ML-DSA-65/ML-KEM-768",
            )
            db.add(recipient)
            db.commit()
            db.refresh(recipient)
            storage_dir = Path(__file__).resolve().parents[2] / "storage" / "keys"
            storage_dir.mkdir(parents=True, exist_ok=True)
            key_file = storage_dir / f"{recipient.recipient_id}.json"
            key_file.write_text(json.dumps({
                "name": name,
                "department": department,
                "ml_dsa_private": dsa_priv,
                "ml_kem_private": kem_priv,
            }, sort_keys=True), encoding="utf-8")
            return RecipientService.to_dict(recipient)
        finally:
            db.close()

    @staticmethod
    def list_recipients() -> list[dict]:
        db: Session = SessionLocal()
        try:
            return [RecipientService.to_dict(r) for r in db.query(Recipient).order_by(Recipient.id).all()]
        finally:
            db.close()

    @staticmethod
    def get_recipient(recipient_id: str) -> dict | None:
        db: Session = SessionLocal()
        try:
            recipient = db.query(Recipient).filter(Recipient.recipient_id == recipient_id).first()
            return None if recipient is None else RecipientService.to_dict(recipient)
        finally:
            db.close()

    @staticmethod
    def get_private_keys(recipient_id: str) -> dict | None:
        key_file = Path(__file__).resolve().parents[2] / 'storage' / 'keys' / f'{recipient_id}.json'
        if not key_file.exists():
            return None
        return json.loads(key_file.read_text(encoding='utf-8'))

    @staticmethod
    def to_dict(recipient: Recipient) -> dict:
        return {
            "id": recipient.id,
            "recipient_id": recipient.recipient_id,
            "name": recipient.name,
            "department": recipient.department,
            "public_key": recipient.public_key,
            "key_algorithm": recipient.key_algorithm,
            "created_at": recipient.created_at.isoformat() if recipient.created_at else None,
            "active": recipient.active,
        }
