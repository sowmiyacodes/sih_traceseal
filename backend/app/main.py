from __future__ import annotations

from contextlib import asynccontextmanager
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.crypto import router as crypto_router
from app.api.auth import router as auth_router
from app.api.documents import router as documents_router
from app.api.forensics import router as forensics_router
from app.api.ledger import router as ledger_router
from app.api.recipients import router as recipients_router
from app.api.watermark import router as watermark_router
from app.api.notifications import router as notifications_router
from app.models.database import init_db
from app.api.auth import current_user
from app.services.auth_service import AuthService
from fastapi import Depends

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if os.environ.get('TRACESEAL_SEED_DEMO', '').lower() in {'1', 'true', 'yes'}:
        AuthService.seed_admin()
        AuthService.seed_demo_recipient()
    yield


app = FastAPI(title="Forensic Document Attribution System", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(recipients_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(documents_router, prefix="/api")
app.include_router(watermark_router, prefix="/api")
app.include_router(notifications_router, prefix="/api")
app.include_router(crypto_router, prefix="/api")
app.include_router(ledger_router, prefix="/api")
app.include_router(forensics_router, prefix="/api")


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "forensic-document-system"}


@app.get('/api/system/status')
def system_status(_: dict = Depends(current_user)):
    from app.crypto.pq import is_real_pqc_available
    from app.services.audit_service import AuditService
    from app.services.ledger_service import LedgerService
    from app.services.watermark_service import WatermarkService
    from app.models.database import engine

    ledger = LedgerService.verify_chain()
    storage_ok = Path(__file__).resolve().parents[1].joinpath('storage').exists()
    database_ok = False
    try:
        with engine.connect():
            database_ok = True
    except Exception:
        database_ok = False
    return {
        'deployment': 'OFFLINE / AIR-GAPPED',
        'authentication': 'READY',
        'authorization': 'READY',
        'pqc': 'REAL LIBOQS' if is_real_pqc_available() else 'LOCAL COMPATIBILITY MODE',
        'pqc_reason': 'Native liboqs is loaded.' if is_real_pqc_available() else 'Running offline without liboqs. ML-KEM/ML-DSA interoperability is disabled; local compatibility signing and key wrapping are enabled for development.',
        'ml_kem': is_real_pqc_available(),
        'ml_dsa': is_real_pqc_available(),
        'watermark_engine': WatermarkService.ALGORITHM,
        'ledger': ledger,
        'database': database_ok,
        'storage': storage_ok,
        'audit_logging': bool(AuditService.list_recent(1) is not None),
    }


@app.get('/api/audit/events')
def audit_events(_: dict = Depends(current_user)):
    from app.services.audit_service import AuditService
    return AuditService.list_recent()


@app.get("/api/dashboard")
def dashboard(_: dict = Depends(current_user)):
    from app.services.document_service import DocumentService
    from app.services.recipient_service import RecipientService
    from app.services.ledger_service import LedgerService
    from app.services.decryption_service import DecryptionService
    from app.services.watermark_service import WatermarkService
    from app.services.forensic_case_service import ForensicCaseService
    from app.crypto.pq import is_real_pqc_available

    docs = DocumentService.list_documents()
    recipients = RecipientService.list_recipients()
    ledger = LedgerService.list_blocks()
    events = DecryptionService.list_events()
    watermarks = WatermarkService.list_watermarks()
    cases = ForensicCaseService.list_cases()
    return {
        "total_documents": len(docs),
        "encrypted_documents": sum(1 for d in docs if d.get("encrypted_path")),
        "registered_recipients": len(recipients),
        "decryption_events": len(events),
        "watermark_records": len(watermarks),
        "ledger_blocks": len(ledger),
        "ledger_integrity": LedgerService.validate_chain(),
        "forensic_cases": len(cases),
        "confirmed_attributions": sum(1 for case in cases if case.get('attribution_confirmed')),
        "pqc_status": "ML-KEM-768 / ML-DSA-65 (liboqs)" if is_real_pqc_available() else "DEVELOPMENT FALLBACK (liboqs unavailable)",
        "watermark_engine": "DCT",
    }
