from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String

from app.models.database import Base


class Watermark(Base):
    __tablename__ = "watermarks"

    id = Column(Integer, primary_key=True, index=True)
    watermark_id = Column(String(64), unique=True, index=True, nullable=False)
    document_id = Column(String(32), nullable=False)
    recipient_id = Column(String(32), nullable=False)
    document_hash = Column(String(128), nullable=False, default='')
    session_id = Column(String(64), nullable=False)
    nonce = Column(String(128), nullable=False)
    timestamp = Column(String(64), nullable=False, default='')
    watermark_hash = Column(String(128), nullable=False)
    algorithm = Column(String(32), nullable=False, default='DCT')
    confidence = Column(Float, nullable=False, default=1.0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
