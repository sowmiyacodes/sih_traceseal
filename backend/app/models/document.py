from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.models.database import Base


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(String(32), unique=True, index=True, nullable=False)
    original_filename = Column(String(255), nullable=False)
    encrypted_path = Column(String(512), nullable=True)
    decrypted_path = Column(String(512), nullable=True)
    watermarked_path = Column(String(512), nullable=True)
    original_hash = Column(String(128), nullable=True)
    encryption_algorithm = Column(String(64), nullable=False, default="AES-256-GCM")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
