from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.watermark_service import WatermarkService

router = APIRouter(tags=['watermark'])


class WatermarkRequest(BaseModel):
    document_path: str
    recipient_id: str
    document_id: str
    session_id: str
    nonce: str


@router.post('/watermark/embed')
def embed(request: WatermarkRequest):
    try:
        return WatermarkService.embed_watermark(request.document_path, request.recipient_id, request.document_id, request.session_id, request.nonce)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post('/watermark/detect')
def detect(payload: dict):
    path = payload.get('document_path')
    if not path:
        raise HTTPException(status_code=400, detail='document_path is required')
    return WatermarkService.detect_watermark(path)


@router.post('/watermark/extract')
def extract(payload: dict):
    path = payload.get('document_path')
    if not path:
        raise HTTPException(status_code=400, detail='document_path is required')
    return WatermarkService.extract_watermark(path)
