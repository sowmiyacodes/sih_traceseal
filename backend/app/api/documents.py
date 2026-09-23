from __future__ import annotations

import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.services.document_service import DocumentService
from app.services.decryption_service import DecryptionService
from app.services.watermark_service import WatermarkService
from app.services.recipient_service import RecipientService
from app.crypto.hashing import sha3_256_hex
from app.api.auth import require_roles, current_user
from app.services.audit_service import AuditService

router = APIRouter(tags=['documents'])


class DecryptRequest(BaseModel):
    document_id: str
    recipient_id: str | None = None


class DistributionRequest(BaseModel):
    recipient_ids: list[str]


class DocumentUpdateRequest(BaseModel):
    original_filename: str


@router.post('/documents/upload')
async def upload_document(file: UploadFile = File(...), _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    if file is None or not file.filename:
        raise HTTPException(status_code=400, detail='No file uploaded.')
    try:
        result = DocumentService.upload_document(file)
        AuditService.record('DOCUMENT_UPLOAD', actor_id=_['user_id'], subject_id=result['document_id'])
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post('/documents/decrypt')
def decrypt_document(payload: DecryptRequest, user: dict = Depends(current_user)):
    try:
        document_id = payload.document_id
        recipient_id = payload.recipient_id or user.get('recipient_id')
        if user['role'] == 'RECIPIENT':
            if not user.get('recipient_id') or recipient_id != user['recipient_id']:
                raise HTTPException(status_code=403, detail='Recipient is not authorized for this package')
        if not recipient_id:
            raise ValueError('Recipient decryption requires a RECIPIENT account linked to a recipient ID. Log out and sign in as the authorized recipient.')
        package = DocumentService.decrypt_recipient_package(document_id, recipient_id)
        document = DocumentService.get_document(document_id)
        if document is None:
            raise ValueError('Document not found')
        result = DocumentService.decrypt_document_file(document['encrypted_path'], package['key'], document_id)
        session_id = DecryptionService.generate_session_id()
        watermark = WatermarkService.embed_watermark(
            result['plaintext_path'],
            recipient_id,
            document_id,
            session_id,
            secrets.token_hex(8),
            document_hash=result['sha3_256'],
        )
        DocumentService.set_watermarked_path(document_id, watermark['output_path'])
        event = DecryptionService.create_decryption_event(
            document_id=document_id,
            recipient_id=recipient_id,
            session_id=session_id,
            watermark_id=watermark['watermark_id'],
            document_hash=result['sha3_256'],
            watermarked_hash=sha3_256_hex(Path(watermark['output_path']).read_bytes()),
            private_key=(RecipientService.get_private_keys(recipient_id) or {}).get('ml_dsa_private'),
        )
        AuditService.record('DECRYPTION', actor_id=user['user_id'], subject_id=event['event_id'], details={'document_id': document_id, 'watermark_id': watermark['watermark_id']})
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
            "download_url": f"/api/documents/{document_id}/download?watermark_id={watermark['watermark_id']}",
            "download_filename": document['original_filename'],
        }
    except InvalidTag as exc:
        raise HTTPException(status_code=400, detail='Decryption failed: the key does not match this encrypted document.') from exc
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post('/documents/{document_id}/distribution')
def distribute_document(document_id: str, payload: DistributionRequest, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    try:
        packages = DocumentService.create_recipient_packages(document_id, payload.recipient_ids)
        AuditService.record('DOCUMENT_ASSIGNMENT', actor_id=_['user_id'], subject_id=document_id, details={'recipients': payload.recipient_ids})
        return {'document_id': document_id, 'packages': packages, 'ciphertext_count': 1}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get('/documents/{document_id}/packages')
def list_packages(document_id: str, user: dict = Depends(current_user)):
    recipient_id = user.get('recipient_id') if user['role'] == 'RECIPIENT' else None
    return DocumentService.list_recipient_packages(document_id=document_id, recipient_id=recipient_id)


@router.get('/documents/{document_id}/download')
def download_watermarked_copy(document_id: str, watermark_id: str, user: dict = Depends(current_user)):
    if user['role'] != 'RECIPIENT' or not user.get('recipient_id'):
        raise HTTPException(status_code=403, detail='Only the authenticated recipient can download a watermarked copy')
    watermark = WatermarkService.get_watermark(watermark_id)
    if watermark is None or watermark['document_id'] != document_id or watermark['recipient_id'] != user['recipient_id']:
        raise HTTPException(status_code=403, detail='Watermark is not assigned to this recipient')
    matches = list((DocumentService.STORAGE_ROOT / 'watermarked').glob(f'*{watermark_id}*'))
    if not matches:
        raise HTTPException(status_code=404, detail='Watermarked copy not found')
    document = DocumentService.get_document(document_id)
    filename = document['original_filename'] if document else 'document'
    media_type = 'application/pdf' if Path(filename).suffix.lower() == '.pdf' else 'application/octet-stream'
    return FileResponse(matches[0], filename=filename, media_type=media_type)


@router.get('/documents')
def list_documents(user: dict = Depends(current_user)):
    recipient_id = user.get('recipient_id') if user['role'] == 'RECIPIENT' else None
    return DocumentService.list_documents(recipient_id=recipient_id)


@router.get('/documents/{document_id}')
def get_document(document_id: str, user: dict = Depends(current_user)):
    doc = DocumentService.get_document(document_id)
    if doc is None:
        raise HTTPException(status_code=404, detail='Document not found')
    if user['role'] == 'RECIPIENT':
        assigned = DocumentService.list_recipient_packages(document_id=document_id, recipient_id=user.get('recipient_id'))
        if not assigned:
            raise HTTPException(status_code=403, detail='Document is not assigned to this recipient')
    return doc


@router.get('/documents/{document_id}/key')
def get_document_key(document_id: str, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    raise HTTPException(status_code=410, detail='Document keys are server-side and never returned by the API')


@router.delete('/documents/{document_id}')
def delete_document(document_id: str, _: dict = Depends(require_roles('ADMIN'))):
    try:
        DocumentService.delete_document(document_id)
        return {'document_id': document_id, 'deleted': True}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch('/documents/{document_id}')
def update_document(document_id: str, payload: DocumentUpdateRequest, _: dict = Depends(require_roles('ADMIN'))):
    try:
        return DocumentService.update_document(document_id, payload.original_filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
