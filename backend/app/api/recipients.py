from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.recipient_service import RecipientService

router = APIRouter(tags=['recipients'])


class RecipientCreateRequest(BaseModel):
    name: str
    department: str


@router.post('/recipients')
def create_recipient(payload: RecipientCreateRequest):
    if not payload.name or not payload.department:
        raise HTTPException(status_code=400, detail='Name and department are required')
    return RecipientService.create_recipient(payload.name, payload.department)


@router.get('/recipients')
def list_recipients():
    return RecipientService.list_recipients()
