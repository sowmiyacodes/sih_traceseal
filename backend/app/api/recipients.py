from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.services.recipient_service import RecipientService
from app.api.auth import current_user, require_roles

router = APIRouter(tags=['recipients'])


class RecipientCreateRequest(BaseModel):
    name: str
    department: str


@router.post('/recipients')
def create_recipient(payload: RecipientCreateRequest, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    if not payload.name or not payload.department:
        raise HTTPException(status_code=400, detail='Name and department are required')
    return RecipientService.create_recipient(payload.name, payload.department)


@router.get('/recipients')
def list_recipients(_: dict = Depends(current_user)):
    return RecipientService.list_recipients()
