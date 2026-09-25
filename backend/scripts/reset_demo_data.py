from __future__ import annotations

import shutil
import sys
import os
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.models.database import Base, SessionLocal, engine
from app.models.document import Document
from app.models.recipient import Recipient
from app.models.watermark import Watermark
from app.models.decryption_event import DecryptionEvent
from app.models.user import User
from app.models.recipient_package import RecipientPackage
from app.services.auth_service import AuthService
from app.services.document_service import DocumentService


def reset_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def main() -> None:
    storage = DocumentService.STORAGE_ROOT
    ledger = BACKEND_ROOT / 'ledger_data'
    engine.dispose()
    if storage.exists():
        shutil.rmtree(storage)
    if ledger.exists():
        shutil.rmtree(ledger)
    storage.mkdir(parents=True, exist_ok=True)
    reset_database()
    print('Reset complete. No users or demo records were created.')


if __name__ == '__main__':
    main()
