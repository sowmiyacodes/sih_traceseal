from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text, UniqueConstraint

from app.models.database import Base


class RecipientPackage(Base):
    __tablename__ = "recipient_packages"
    __table_args__ = (UniqueConstraint("document_id", "recipient_id", name="uq_document_recipient_package"),)

    id = Column(Integer, primary_key=True, index=True)
    package_id = Column(String(64), unique=True, index=True, nullable=False)
    document_id = Column(String(32), index=True, nullable=False)
    recipient_id = Column(String(32), index=True, nullable=False)
    kem_ciphertext = Column(Text, nullable=False)
    wrapped_key = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
