from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text, UniqueConstraint

from app.models.database import Base


class RecipientPackage(Base):
    __tablename__ = "recipient_packages"
    __table_args__ = (
        UniqueConstraint("document_id", "recipient_id", name="uq_document_recipient_package"),
        UniqueConstraint("trace_id", name="uq_trace_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    package_id = Column(String(64), unique=True, index=True, nullable=False)
    document_id = Column(String(32), index=True, nullable=False)
    recipient_id = Column(String(32), index=True, nullable=False)
    trace_id = Column(String(64), unique=True, index=True, nullable=False, default="TS-UNKNOWN")
    issue_timestamp = Column(String(64), nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    expiry_timestamp = Column(String(64), nullable=True)
    permissions = Column(Text, nullable=False, default='{"view": true, "download": true, "print": false, "edit": false, "reshare": false}')
    max_downloads = Column(Integer, nullable=True)
    view_count = Column(Integer, nullable=False, default=0)
    download_count = Column(Integer, nullable=False, default=0)
    status = Column(String(32), nullable=False, default="ACTIVE")
    revocation_reason = Column(Text, nullable=True)
    revoked_by = Column(String(64), nullable=True)
    revoked_at = Column(String(64), nullable=True)
    last_accessed_at = Column(String(64), nullable=True)
    kem_ciphertext = Column(Text, nullable=False)
    wrapped_key = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
