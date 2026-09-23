from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.api.auth import current_user
from app.models.database import SessionLocal
from app.models.decryption_event import DecryptionEvent
from app.models.document import Document
from app.models.recipient_package import RecipientPackage

router = APIRouter(tags=['notifications'])


@router.get('/notifications')
def notifications(user: dict = Depends(current_user)):
    if user['role'] != 'RECIPIENT' or not user.get('recipient_id'):
        return {'items': [], 'unread': 0}
    db = SessionLocal()
    try:
        recipient_id = user['recipient_id']
        packages = db.query(RecipientPackage, Document).join(Document, Document.document_id == RecipientPackage.document_id).filter(RecipientPackage.recipient_id == recipient_id).order_by(RecipientPackage.created_at.desc()).all()
        events = db.query(DecryptionEvent, Document).join(Document, Document.document_id == DecryptionEvent.document_id).filter(DecryptionEvent.recipient_id == recipient_id).order_by(DecryptionEvent.created_at.desc()).all()
        items = []
        for package, document in packages:
            items.append({
                'id': f'package-{package.package_id}',
                'type': 'ASSIGNMENT',
                'title': 'New protected document',
                'message': f'{document.original_filename} is ready to decrypt.',
                'document_id': document.document_id,
                'timestamp': package.created_at.isoformat() if package.created_at else None,
                'read': False,
            })
        for event, document in events:
            items.append({
                'id': f'event-{event.event_id}',
                'type': 'DOWNLOAD',
                'title': 'Protected copy created',
                'message': f'Your watermarked copy of {document.original_filename} was created.',
                'document_id': document.document_id,
                'event_id': event.event_id,
                'timestamp': event.created_at.isoformat() if event.created_at else event.timestamp,
                'read': True,
            })
        items.sort(key=lambda item: item.get('timestamp') or '', reverse=True)
        return {'items': items[:50], 'unread': sum(1 for item in items if not item['read'])}
    finally:
        db.close()
