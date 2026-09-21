from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from app.models.database import Base


class Recipient(Base):
    __tablename__ = "recipients"

    id = Column(Integer, primary_key=True, index=True)
    recipient_id = Column(String(32), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    department = Column(String(128), nullable=False)
    public_key = Column(Text, nullable=False)
    key_algorithm = Column(String(64), nullable=False, default="ML-DSA-65")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    active = Column(Boolean, default=True)
