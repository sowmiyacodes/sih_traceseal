from __future__ import annotations

from contextlib import asynccontextmanager
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
from app.models.database import init_db
from app.api.auth import current_user
from app.services.auth_service import AuthService
from fastapi import Depends

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    AuthService.seed_admin()
    yield


app = FastAPI(title="Forensic Document Attribution System", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(recipients_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(documents_router, prefix="/api")
app.include_router(watermark_router, prefix="/api")
app.include_router(crypto_router, prefix="/api")
app.include_router(ledger_router, prefix="/api")
app.include_router(forensics_router, prefix="/api")


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "forensic-document-system"}


@app.get("/api/dashboard")
def dashboard(_: dict = Depends(current_user)):
    from app.services.document_service import DocumentService
    from app.services.recipient_service import RecipientService
    from app.services.ledger_service import LedgerService
    from app.services.decryption_service import DecryptionService
    from app.services.watermark_service import WatermarkService
    from app.services.forensic_case_service import ForensicCaseService

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
        "pqc_status": "ML-KEM-768 / ML-DSA-65",
        "watermark_engine": "DCT",
    }
