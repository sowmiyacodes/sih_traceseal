from __future__ import annotations

import shutil
import sys
from pathlib import Path

import cv2
import numpy as np

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.models.database import Base, SessionLocal, engine
from app.services.document_service import DocumentService
from app.services.watermark_service import WatermarkService
from app.services.recipient_service import RecipientService


DEMO_DOCUMENTS = [
    (
        'case-brief.png',
        'TraceSeal sample case brief. This file is encrypted locally for the demo workflow.',
        '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    ),
    (
        'evidence-note.png',
        'TraceSeal sample evidence note. Use this record to test decrypt and file verification.',
        'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100',
    ),
]


def reset_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.close()


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
    RecipientService.create_recipient('Alice Example', 'Forensics')
    RecipientService.create_recipient('Bob Example', 'Compliance')

    source_dir = storage / '_demo_sources'
    source_dir.mkdir(parents=True, exist_ok=True)
    for filename, content, key_hex in DEMO_DOCUMENTS:
        source = source_dir / filename
        canvas = np.full((768, 1024, 3), 248, dtype=np.uint8)
        cv2.putText(canvas, 'TRACESEAL FORENSIC EVIDENCE', (48, 100), cv2.FONT_HERSHEY_SIMPLEX, 1.3, (20, 45, 80), 3, cv2.LINE_AA)
        cv2.putText(canvas, content, (48, 180), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (65, 80, 105), 2, cv2.LINE_AA)
        cv2.imwrite(str(source), canvas)
        marked = WatermarkService.embed_watermark(source, 'DEMO', f'DEMO-{filename.split(".", 1)[0].upper()}', 'DEMO-SESSION', 'DEMO-NONCE')
        source.write_bytes(Path(marked['output_path']).read_bytes())
        result = DocumentService.encrypt_document_file(source, 'DEMO', bytes.fromhex(key_hex))
        key_path = storage / 'keys' / f"{result['document_id']}.key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(key_hex, encoding='ascii')
        DocumentService.decrypt_document_file(result['encrypted_path'], bytes.fromhex(key_hex), result['document_id'])

    shutil.rmtree(source_dir)
    print('Reset complete: created exactly 2 encrypted demo documents.')
    for filename, _, key_hex in DEMO_DOCUMENTS:
        print(f'{filename}: {key_hex}')


if __name__ == '__main__':
    main()
