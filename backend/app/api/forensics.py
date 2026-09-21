from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.decryption_service import DecryptionService
from app.services.forensic_case_service import ForensicCaseService
from app.services.ledger_service import LedgerService
from app.services.recipient_service import RecipientService
from app.services.watermark_service import WatermarkService

router = APIRouter(tags=['forensics'])


class AnalyzeRequest(BaseModel):
    document_path: str


class VerifyLedgerRequest(BaseModel):
    watermark_id: str | None = None
    event_id: str | None = None


@router.post('/forensics/analyze')
def analyze(payload: AnalyzeRequest):
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
    try:
        public_key = (json.loads(recipient['public_key']) if recipient else {}).get('ml_dsa_public')
        signature_valid = bool(public_key and event.get('signature') and DecryptionService.verify_decryption_event(public_key, event['event_hash'], event['signature']))
    except (TypeError, ValueError, json.JSONDecodeError):
        signature_valid = False
    chain_valid = LedgerService.validate_chain()
    attribution_confirmed = bool(recipient and signature_valid and chain_valid)
    case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{event_id[-6:]}"
    case = {
        'case_id': case_id,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'evidence_sha3_256': detection.get('watermark_id', ''),
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
        'chain_valid': chain_valid,
        'recipient': {
            'recipient_id': event['recipient_id'],
            'display_name': recipient['name'] if recipient else 'unknown',
            'public_key_fingerprint': (recipient['public_key'] or '')[:16] if recipient else None,
        } if recipient else None,
        'attribution_confirmed': attribution_confirmed,
    }
    ForensicCaseService.create_case(case)
    return case


@router.post('/ledger/verify')
def verify_ledger(payload: VerifyLedgerRequest):
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
def get_event(event_id: str):
    event = DecryptionService.get_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail='Event not found')
    return event


@router.get('/watermarks/{watermark_id}')
def get_watermark(watermark_id: str):
    watermark = WatermarkService.get_watermark(watermark_id)
    if watermark is None:
        raise HTTPException(status_code=404, detail='Watermark not found')
    return watermark


@router.get('/ledger/watermark/{watermark_id}')
def get_ledger_by_watermark(watermark_id: str):
    rows = LedgerService.find_by_watermark(watermark_id)
    return {'watermark_id': watermark_id, 'matches': rows}


@router.get('/ledger/event/{event_id}')
def get_ledger_by_event(event_id: str):
    rows = LedgerService.find_by_event_id(event_id)
    return {'event_id': event_id, 'matches': rows}


@router.get('/forensics/cases')
def list_cases():
    return ForensicCaseService.list_cases()


@router.get('/forensics/cases/{case_id}')
def get_case(case_id: str):
    case = ForensicCaseService.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail='Case not found')
    return case
