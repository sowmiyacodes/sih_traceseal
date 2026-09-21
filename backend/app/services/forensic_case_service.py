from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class ForensicCaseService:
    STORAGE_ROOT = Path(__file__).resolve().parents[2] / "storage"
    CASES_DIR = STORAGE_ROOT / "cases"

    @staticmethod
    def _ensure_storage() -> None:
        ForensicCaseService.CASES_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def create_case(payload: dict) -> dict:
        ForensicCaseService._ensure_storage()
        case_id = payload.get("case_id") or f"CASE-{uuid4().hex[:12].upper()}"
        case = {
            "case_id": case_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        case_path = ForensicCaseService.CASES_DIR / f"{case_id}.json"
        case_path.write_text(json.dumps(case, indent=2, sort_keys=True), encoding="utf-8")
        return case

    @staticmethod
    def list_cases() -> list[dict]:
        ForensicCaseService._ensure_storage()
        results = []
        for file in sorted(ForensicCaseService.CASES_DIR.glob("*.json")):
            try:
                results.append(json.loads(file.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
        return results

    @staticmethod
    def get_case(case_id: str) -> dict | None:
        case_path = ForensicCaseService.CASES_DIR / f"{case_id}.json"
        if not case_path.exists():
            return None
        try:
            return json.loads(case_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
