from __future__ import annotations

import json
from typing import Any

from app.models.audit_event import AuditEvent
from app.models.database import SessionLocal


class AuditService:
    @staticmethod
    def record(event_type: str, actor_id: str | None = None, subject_id: str | None = None, outcome: str = "SUCCESS", details: dict[str, Any] | None = None) -> None:
        db = SessionLocal()
        try:
            db.add(AuditEvent(
                event_type=event_type,
                actor_id=actor_id,
                subject_id=subject_id,
                outcome=outcome,
                details=json.dumps(details or {}, sort_keys=True, separators=(",", ":")),
            ))
            db.commit()
        finally:
            db.close()

    @staticmethod
    def list_recent(limit: int = 20) -> list[dict[str, Any]]:
        db = SessionLocal()
        try:
            rows = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(max(1, min(limit, 100))).all()
            return [{
                "event_type": row.event_type,
                "actor_id": row.actor_id,
                "subject_id": row.subject_id,
                "outcome": row.outcome,
                "details": json.loads(row.details or "{}"),
                "created_at": row.created_at.isoformat() if row.created_at else None,
            } for row in rows]
        finally:
            db.close()
