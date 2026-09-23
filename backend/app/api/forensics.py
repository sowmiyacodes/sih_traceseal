from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.services.decryption_service import DecryptionService
from app.services.forensic_case_service import ForensicCaseService
from app.services.ledger_service import LedgerService
from app.services.recipient_service import RecipientService
from app.services.watermark_service import WatermarkService
from app.services.document_service import DocumentService
from app.api.auth import current_user, require_roles
from app.crypto.hashing import sha3_256_hex

router = APIRouter(tags=['forensics'])


class AnalyzeRequest(BaseModel):
    document_path: str


class VerifyLedgerRequest(BaseModel):
    watermark_id: str | None = None
    event_id: str | None = None


@router.post('/forensics/analyze')
def analyze(payload: AnalyzeRequest, user: dict = Depends(require_roles('ADMIN', 'FORENSIC_INVESTIGATOR'))):
    evidence_path = __import__('pathlib').Path(payload.document_path)
    if not evidence_path.exists():
        raise HTTPException(status_code=400, detail='Evidence file not found')
    evidence_hash = sha3_256_hex(evidence_path.read_bytes())
    detection = WatermarkService.detect_watermark(payload.document_path)
    if not detection.get('detected') or not detection.get('watermark_id'):
        return {
            'case_id': None,
            'watermark': {
                'detected': False,
                'watermark_id': None,
                'confidence': detection.get('confidence', 0.0),
                'page': detection.get('page', 1),
                'algorithm': detection.get('algorithm', 'TRACESEAL-TEXT'),
            },
            'ledger_match': False,
            'event_id': None,
            'signature_valid': False,
            'chain_valid': LedgerService.validate_chain(),
            'recipient': None,
            'attribution_confirmed': False,
            'failure': 'watermark_not_detected',
        }

    match = LedgerService.find_by_watermark(detection['watermark_id'])
    event_id = match[0].get('event_id') if match else None
    event = DecryptionService.get_event_by_id(event_id) if event_id else None
    if event is None:
        return {
            'case_id': None,
            'watermark': {
                'detected': True,
                'watermark_id': detection['watermark_id'],
                'confidence': detection.get('confidence', 0.0),
                'page': detection.get('page', 1),
                'algorithm': detection.get('algorithm', 'TRACESEAL-TEXT'),
            },
            'ledger_match': False,
            'event_id': None,
            'signature_valid': False,
            'chain_valid': LedgerService.validate_chain(),
            'recipient': None,
            'attribution_confirmed': False,
            'failure': 'ledger_miss',
        }

    recipient = RecipientService.get_recipient(event['recipient_id'])
    signature_valid = False
    public_key_match = False
    try:
        public_key = (json.loads(recipient['public_key']) if recipient else {}).get('ml_dsa_public')
        signature_valid = bool(public_key and event.get('signature') and DecryptionService.verify_decryption_event(public_key, event['event_hash'], event['signature']))
        public_key_match = bool(public_key and event.get('public_key_fingerprint') and sha3_256_hex(bytes.fromhex(public_key)) == event['public_key_fingerprint'])
    except (TypeError, ValueError, json.JSONDecodeError):
        signature_valid = False
    chain_valid = LedgerService.verify_chain()['valid']
    evidence_hash_match = event.get('watermarked_hash') == evidence_hash
    document = DocumentService.get_document(event['document_id'])
    evidence_recorded = bool(document and event.get('document_hash') == document.get('original_hash'))
    attribution_confirmed = bool(recipient and signature_valid and public_key_match and chain_valid and evidence_hash_match and evidence_recorded)
    case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{event_id[-6:]}"
    case = {
        'case_id': case_id,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'investigator_id': user['user_id'],
        'evidence_filename': evidence_path.name,
        'evidence_sha3_256': evidence_hash,
        'watermark': {
            'detected': True,
            'watermark_id': detection['watermark_id'],
            'confidence': detection.get('confidence', 0.0),
            'page': detection.get('page', 1),
            'algorithm': detection.get('algorithm', 'TRACESEAL-TEXT'),
        },
        'ledger_match': True,
        'event_id': event_id,
        'signature_valid': signature_valid,
        'public_key_match': public_key_match,
        'chain_valid': chain_valid,
        'evidence_hash_match': evidence_hash_match,
        'evidence_hash_recorded': evidence_recorded,
        'recipient': {
            'recipient_id': event['recipient_id'],
            'display_name': recipient['name'] if recipient else 'unknown',
            'public_key_fingerprint': event.get('public_key_fingerprint'),
        } if recipient else None,
        'attribution_confirmed': attribution_confirmed,
    }
    ForensicCaseService.create_case(case)
    return case


@router.post('/forensics/analyze-upload')
async def analyze_upload(file: UploadFile = File(...), user: dict = Depends(require_roles('ADMIN', 'FORENSIC_INVESTIGATOR'))):
    if not file.filename:
        raise HTTPException(status_code=400, detail='Evidence file is required')
    evidence_dir = Path(__file__).resolve().parents[2] / 'storage' / 'evidence'
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / Path(file.filename).name
    target.write_bytes(await file.read())
    return analyze(AnalyzeRequest(document_path=str(target)), user)


@router.get('/forensics/cases/{case_id}/report', response_class=HTMLResponse)
def report(case_id: str, _: dict = Depends(current_user)):
    case = ForensicCaseService.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail='Case not found')
    recipient = case.get('recipient') or {}
    status = 'ATTRIBUTION CONFIRMED' if case.get('attribution_confirmed') else 'ATTRIBUTION NOT CONFIRMED'
    html = f'''<!doctype html><html><head><meta charset="utf-8"><title>TraceSeal {case_id}</title></head><body><h1>TraceSeal Forensic Report</h1><h2>{status}</h2><h3>Observed Evidence</h3><p>Case ID: {case_id}</p><p>Evidence filename: {case.get('evidence_filename', 'unknown')}</p><p>Evidence SHA3-256: {case.get('evidence_sha3_256', 'unknown')}</p><p>Watermark ID: {(case.get('watermark') or {}).get('watermark_id', 'not found')}</p><h3>Verification Results</h3><p>Ledger match: {case.get('ledger_match')}</p><p>Signature valid: {case.get('signature_valid')}</p><p>Public key match: {case.get('public_key_match')}</p><p>Ledger chain valid: {case.get('chain_valid')}</p><p>Evidence hash recorded: {case.get('evidence_hash_recorded')}</p><h3>Attribution Result</h3><p>Recipient: {recipient.get('display_name', 'unknown')} ({recipient.get('recipient_id', 'unknown')})</p><p>Event ID: {case.get('event_id', 'unknown')}</p></body></html>'''
    return HTMLResponse(html)


@router.post('/ledger/verify')
def verify_ledger(payload: VerifyLedgerRequest, _: dict = Depends(current_user)):
    chain_valid = LedgerService.validate_chain()
    event_id = payload.event_id
    watermark_id = payload.watermark_id
    if event_id:
        entry = LedgerService.find_by_event_id(event_id)
        return {'event_id': event_id, 'ledger_match': bool(entry), 'chain_valid': chain_valid}
    if watermark_id:
        entry = LedgerService.find_by_watermark(watermark_id)
        return {'watermark_id': watermark_id, 'ledger_match': bool(entry), 'chain_valid': chain_valid}
    return {'ledger_match': False, 'chain_valid': chain_valid}


@router.get('/events/{event_id}')
def get_event(event_id: str, _: dict = Depends(current_user)):
    event = DecryptionService.get_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail='Event not found')
    return event


@router.get('/watermarks/{watermark_id}')
def get_watermark(watermark_id: str, _: dict = Depends(current_user)):
    watermark = WatermarkService.get_watermark(watermark_id)
    if watermark is None:
        raise HTTPException(status_code=404, detail='Watermark not found')
    return watermark


@router.get('/ledger/watermark/{watermark_id}')
def get_ledger_by_watermark(watermark_id: str, _: dict = Depends(current_user)):
    rows = LedgerService.find_by_watermark(watermark_id)
    return {'watermark_id': watermark_id, 'matches': rows}


@router.get('/ledger/event/{event_id}')
def get_ledger_by_event(event_id: str, _: dict = Depends(current_user)):
    rows = LedgerService.find_by_event_id(event_id)
    return {'event_id': event_id, 'matches': rows}


@router.get('/forensics/cases')
def list_cases(_: dict = Depends(current_user)):
    return ForensicCaseService.list_cases()


@router.get('/forensics/cases/{case_id}')
def get_case(case_id: str, _: dict = Depends(current_user)):
    case = ForensicCaseService.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail='Case not found')
    return case
