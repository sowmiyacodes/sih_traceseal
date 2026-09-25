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
    permissions: dict[str, bool] | None = None
    expiry_timestamp: str | None = None
    max_downloads: int | str | None = None


class DocumentUpdateRequest(BaseModel):
    original_filename: str | None = None
    title: str | None = None
    content: str | None = None


class RevokeDocumentRequest(BaseModel):
    reason: str | None = None
    revoked_by: str | None = None


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
        view_access = DocumentService.can_access_package(document_id, recipient_id, 'VIEW')
        if not view_access['allowed']:
            raise HTTPException(status_code=403, detail='View permission is not granted for this recipient package.')
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


@router.post('/documents/workspace')
def create_document_workspace(payload: DocumentUpdateRequest, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    if (payload.title or '').strip() == '' and (payload.original_filename or '').strip() == '':
        raise HTTPException(status_code=400, detail='Document title is required.')
    try:
        document = DocumentService.create_document(
            title=payload.title or payload.original_filename or 'Untitled document',
            content=payload.content or '',
            original_filename=payload.original_filename,
        )
        AuditService.record('DOCUMENT_CREATE', actor_id=_['user_id'], subject_id=document['document_id'], details={'title': document['title']})
        return document
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post('/documents/{document_id}/distribution')
def distribute_document(document_id: str, payload: DistributionRequest, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    try:
        packages = DocumentService.create_recipient_packages(
            document_id,
            payload.recipient_ids,
            permissions=payload.permissions,
            expiry_timestamp=payload.expiry_timestamp,
            max_downloads=payload.max_downloads,
        )
        AuditService.record('DOCUMENT_ASSIGNMENT', actor_id=_['user_id'], subject_id=document_id, details={
            'recipients': payload.recipient_ids,
            'permissions': payload.permissions or DocumentService.default_permissions(),
            'expiry_timestamp': payload.expiry_timestamp,
            'max_downloads': payload.max_downloads,
        })
        return {'document_id': document_id, 'packages': packages, 'ciphertext_count': 1}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get('/documents/{document_id}/packages')
def list_packages(document_id: str, user: dict = Depends(current_user)):
    recipient_id = user.get('recipient_id') if user['role'] == 'RECIPIENT' else None
    return DocumentService.list_recipient_packages(document_id=document_id, recipient_id=recipient_id)


@router.post('/documents/{document_id}/revoke')
def revoke_distribution(document_id: str, payload: RevokeDocumentRequest, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    try:
        if not payload.reason and not payload.revoked_by:
            payload.reason = 'Access revoked by administrator'
        packages = DocumentService.list_recipient_packages(document_id=document_id)
        if not packages:
            raise ValueError('No active distribution found for this document')
        revoked = []
        for package in packages:
            revoked.append(DocumentService.revoke_distribution(document_id, package['recipient_id'], payload.reason or 'Access revoked by administrator', payload.revoked_by or _['user_id']))
        AuditService.record('DOCUMENT_REVOKE', actor_id=_['user_id'], subject_id=document_id, details={'reason': payload.reason or 'Access revoked by administrator', 'recipients': [item['recipient_id'] for item in packages]})
        return {'document_id': document_id, 'revoked': revoked}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get('/documents/{document_id}/audit')
def document_audit(document_id: str, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    events = AuditService.list_recent(100)
    filtered = [event for event in events if str(event.get('details', '')).find(document_id) > -1 or event.get('subject_id') == document_id]
    packages = DocumentService.list_recipient_packages(document_id=document_id)
    return {'document_id': document_id, 'packages': packages, 'audit_events': filtered}


@router.get('/documents/{document_id}/download')
def download_watermarked_copy(document_id: str, watermark_id: str, user: dict = Depends(current_user)):
    if user['role'] != 'RECIPIENT' or not user.get('recipient_id'):
        raise HTTPException(status_code=403, detail='Only the authenticated recipient can download a watermarked copy')
    allowed = DocumentService.can_access_package(document_id, user['recipient_id'], 'DOWNLOAD')
    if not allowed['allowed']:
        raise HTTPException(status_code=403, detail='Download permission is not granted for this recipient package.')
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
        access = DocumentService.can_access_package(document_id, user['recipient_id'], 'VIEW')
        if not access['allowed']:
            raise HTTPException(status_code=403, detail='View permission is not granted for this recipient package.')
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
        return DocumentService.update_document(
            document_id,
            original_filename=payload.original_filename,
            title=payload.title,
            content=payload.content,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
