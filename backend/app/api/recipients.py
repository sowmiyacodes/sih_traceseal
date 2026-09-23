from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.services.recipient_service import RecipientService
from app.api.auth import current_user, require_roles

router = APIRouter(tags=['recipients'])


class RecipientCreateRequest(BaseModel):
    name: str
    department: str
    username: str | None = None
    password: str | None = None


class RecipientUpdateRequest(BaseModel):
    name: str
    department: str
    active: bool | None = None


@router.post('/recipients')
def create_recipient(payload: RecipientCreateRequest, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    if not payload.name or not payload.department:
        raise HTTPException(status_code=400, detail='Name and department are required')
    recipient = RecipientService.create_recipient(payload.name, payload.department)
    if payload.username and payload.password:
        from app.services.auth_service import AuthService
        AuthService.create_user(payload.username, payload.password, payload.name, 'RECIPIENT', recipient['recipient_id'])
    return recipient


@router.get('/recipients')
def list_recipients(_: dict = Depends(current_user)):
    return RecipientService.list_recipients()


@router.patch('/recipients/{recipient_id}')
def update_recipient(recipient_id: str, payload: RecipientUpdateRequest, _: dict = Depends(require_roles('ADMIN'))):
    try:
        return RecipientService.update_recipient(recipient_id, payload.name, payload.department, payload.active)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete('/recipients/{recipient_id}')
def delete_recipient(recipient_id: str, _: dict = Depends(require_roles('ADMIN'))):
    try:
        RecipientService.delete_recipient(recipient_id)
        return {'recipient_id': recipient_id, 'active': False}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
