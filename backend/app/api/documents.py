from __future__ import annotations

import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.services.document_service import DocumentService
from app.services.decryption_service import DecryptionService
from app.services.watermark_service import WatermarkService
from app.services.recipient_service import RecipientService
from app.crypto.hashing import sha3_256_hex

router = APIRouter(tags=['documents'])


class DecryptRequest(BaseModel):
    document_path: str
    key_hex: str
    document_id: str | None = None
    recipient_id: str = 'REC-DEMO'


@router.post('/documents/upload')
async def upload_document(file: UploadFile = File(...)):
    if file is None or not file.filename:
        raise HTTPException(status_code=400, detail='No file uploaded.')
    return DocumentService.upload_document(file)


@router.post('/documents/decrypt')
def decrypt_document(payload: DecryptRequest):
    try:
        result = DocumentService.decrypt_document_file(payload.document_path, payload.key_hex, payload.document_id)
        document_id = payload.document_id or result['document_id']
        session_id = DecryptionService.generate_session_id()
        watermark = WatermarkService.embed_watermark(result['plaintext_path'], payload.recipient_id, document_id, session_id, secrets.token_hex(8))
        DocumentService.set_watermarked_path(document_id, watermark['output_path'])
        event = DecryptionService.create_decryption_event(
            document_id=document_id,
            recipient_id=payload.recipient_id,
            session_id=session_id,
            watermark_id=watermark['watermark_id'],
            document_hash=result['sha3_256'],
            watermarked_hash=sha3_256_hex(Path(watermark['output_path']).read_bytes()),
            private_key=(RecipientService.get_private_keys(payload.recipient_id) or {}).get('ml_dsa_private'),
        )
        return {
            "document_id": document_id,
            "encrypted_path": result["encrypted_path"],
            "plaintext_path": str(result["plaintext_path"]),
            "watermarked_path": watermark['output_path'],
            "decrypted_bytes": result["decrypted_bytes"],
            "sha3_256": result["sha3_256"],
            "session_id": session_id,
            "watermark_id": watermark['watermark_id'],
            "event_id": event['event_id'],
            "algorithm": watermark['algorithm'],
        }
    except InvalidTag as exc:
        raise HTTPException(status_code=400, detail='Decryption failed: the key does not match this encrypted document.') from exc
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get('/documents')
def list_documents():
    return DocumentService.list_documents()


@router.get('/documents/{document_id}')
def get_document(document_id: str):
    doc = DocumentService.get_document(document_id)
    if doc is None:
        raise HTTPException(status_code=404, detail='Document not found')
    return doc


@router.get('/documents/{document_id}/key')
def get_document_key(document_id: str):
    key = DocumentService.get_document_key(document_id)
    if key is None:
        raise HTTPException(status_code=404, detail='Encryption key is not available for this document')
    return {'document_id': document_id, 'key_hex': key}
