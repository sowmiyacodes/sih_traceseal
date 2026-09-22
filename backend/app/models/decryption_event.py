from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.models.database import Base


class DecryptionEvent(Base):
    __tablename__ = "decryption_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    document_id = Column(String(32), nullable=False)
    recipient_id = Column(String(32), nullable=False)
    session_id = Column(String(64), nullable=False)
    watermark_id = Column(String(64), nullable=False)
    document_hash = Column(String(128), nullable=False)
    watermarked_hash = Column(String(128), nullable=False)
    timestamp = Column(String(64), nullable=False)
    signature = Column(Text, nullable=True)
    signature_algorithm = Column(String(64), nullable=False, default="ML-DSA-65")
    public_key_fingerprint = Column(String(128), nullable=True)
    event_hash = Column(String(128), nullable=False)
    ledger_block_id = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
