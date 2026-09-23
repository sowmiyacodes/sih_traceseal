from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from app.services.decryption_service import DecryptionService
from app.services.forensic_case_service import ForensicCaseService
from app.services.ledger_service import LedgerService
from app.services.recipient_service import RecipientService
from app.services.watermark_service import WatermarkService
from app.services.document_service import DocumentService
from app.api.auth import current_user, require_roles
from app.crypto.hashing import sha3_256_hex
from app.services.audit_service import AuditService

router = APIRouter(tags=['forensics'])


class AnalyzeRequest(BaseModel):
    document_path: str


class VerifyLedgerRequest(BaseModel):
    watermark_id: str | None = None
    event_id: str | None = None


@router.post('/forensics/analyze')
def analyze(payload: AnalyzeRequest, user: dict = Depends(require_roles('ADMIN', 'FORENSIC_INVESTIGATOR'))):
    evidence_path = Path(payload.document_path)
    if not evidence_path.exists():
        raise HTTPException(status_code=400, detail='Evidence file not found')
    evidence_hash = sha3_256_hex(evidence_path.read_bytes())
    detection = WatermarkService.detect_watermark(payload.document_path)
    chain_verification = LedgerService.verify_chain()
    base_result = {
        'match': False,
        'case_id': None,
        'watermark': {
            'detected': bool(detection.get('detected')),
            'watermark_id': detection.get('watermark_id'),
            'confidence': detection.get('confidence', 0.0),
            'page': detection.get('page', 1),
            'algorithm': detection.get('algorithm', 'DCT'),
        },
        'evidence_sha3_256': evidence_hash,
        'ledger_match': False,
        'event_id': None,
        'session_id': None,
        'timestamp': None,
        'watermark_id': detection.get('watermark_id'),
        'signature_valid': False,
        'record_hash_valid': False,
        'watermark_valid': False,
        'document_hash_match': False,
        'public_key_match': False,
        'chain_valid': chain_verification['valid'],
        'checked_blocks': chain_verification.get('checked_blocks', 0),
        'failed_block': chain_verification.get('failed_block'),
        'recipient': None,
        'document': None,
        'attribution_confirmed': False,
    }
    if not detection.get('detected') or not detection.get('watermark_id'):
        AuditService.record('FORENSIC_ANALYSIS', actor_id=user['user_id'], outcome='FAILURE', details={'failure': 'watermark_not_detected'})
        return {**base_result, 'verification_status': 'NO FORENSIC WATERMARK DETECTED', 'failure': 'watermark_not_detected'}

    match = LedgerService.find_by_watermark(detection['watermark_id'])
    event_id = match[0].get('event_id') if match else None
    event = DecryptionService.get_event_by_id(event_id) if event_id else None
    if event is None:
        AuditService.record('FORENSIC_ANALYSIS', actor_id=user['user_id'], outcome='FAILURE', details={'failure': 'ledger_miss', 'watermark_id': detection['watermark_id']})
        return {**base_result, 'verification_status': 'WATERMARK DETECTED - NO MATCHING LEDGER RECORD', 'failure': 'ledger_miss'}

    recipient = RecipientService.get_recipient(event['recipient_id'])
    watermark = WatermarkService.get_watermark(detection['watermark_id'])
    block = LedgerService.find_block_by_event_id(event_id)
    signature_valid = False
    record_hash_valid = False
    public_key_match = False
    try:
        public_key = (json.loads(recipient['public_key']) if recipient else {}).get('ml_dsa_public')
        record_hash_valid = event.get('event_hash') == DecryptionService.event_hash(event)
        signature_valid = bool(public_key and event.get('signature') and record_hash_valid and DecryptionService.verify_decryption_event(public_key, event['event_hash'], event['signature']))
        public_key_match = bool(public_key and event.get('public_key_fingerprint') and sha3_256_hex(bytes.fromhex(public_key)) == event['public_key_fingerprint'])
    except (TypeError, ValueError, json.JSONDecodeError):
        signature_valid = False
    watermark_valid = WatermarkService.verify_watermark_record(watermark, detection['watermark_id'])
    evidence_hash_match = event.get('watermarked_hash') == evidence_hash
    document = DocumentService.get_document(event['document_id'])
    document_hash_match = bool(document and event.get('document_hash') == document.get('original_hash'))
    attribution_confirmed = bool(recipient and block and signature_valid and record_hash_valid and public_key_match and watermark_valid and chain_verification['valid'] and evidence_hash_match and document_hash_match)
    case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{event_id[-6:]}"
    case = {
        **base_result,
        'match': bool(match),
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
        'ledger_match': bool(match and block),
        'event_id': event_id,
        'session_id': event.get('session_id'),
        'timestamp': event.get('timestamp'),
        'watermark_id': event.get('watermark_id'),
        'signature_valid': signature_valid,
        'record_hash_valid': record_hash_valid,
        'watermark_valid': watermark_valid,
        'public_key_match': public_key_match,
        'chain_valid': chain_verification['valid'],
        'evidence_hash_match': evidence_hash_match,
        'document_hash_match': document_hash_match,
        'evidence_hash_recorded': evidence_hash_match,
        'document': {
            'document_id': event['document_id'],
            'name': document['original_filename'] if document else None,
            'hash': document.get('original_hash') if document else event.get('document_hash'),
        },
        'recipient': {
            'recipient_id': event['recipient_id'],
            'display_name': recipient['name'] if recipient else 'unknown',
            'public_key_fingerprint': event.get('public_key_fingerprint'),
        } if recipient else None,
        'attribution_confirmed': attribution_confirmed,
        'block': {
            'block_number': block.get('block_number'),
            'previous_hash': block.get('previous_hash'),
            'block_hash': block.get('block_hash'),
            'record_hash': event.get('event_hash'),
        } if block else None,
        'verification_status': 'CRYPTOGRAPHICALLY VERIFIED FORENSIC MATCH' if attribution_confirmed else 'FORENSIC RECORD FOUND - CRYPTOGRAPHIC VERIFICATION FAILED',
        'evidence_graph': {
            'nodes': [
                {'id': 'document', 'type': 'DOCUMENT', 'label': document['original_filename'] if document else event['document_id'], 'status': 'PASS' if document_hash_match else 'FAIL'},
                {'id': 'recipient', 'type': 'RECIPIENT', 'label': recipient['name'] if recipient else event['recipient_id'], 'status': 'PASS' if recipient else 'FAIL'},
                {'id': 'session', 'type': 'SESSION', 'label': event['session_id'], 'status': 'PASS'},
                {'id': 'watermark', 'type': 'WATERMARK', 'label': event['watermark_id'], 'status': 'PASS' if watermark_valid else 'FAIL'},
                {'id': 'event', 'type': 'DECRYPTION EVENT', 'label': event_id, 'status': 'PASS' if record_hash_valid else 'FAIL'},
                {'id': 'signature', 'type': 'ML-DSA SIGNATURE', 'label': event['signature_algorithm'], 'status': 'PASS' if signature_valid else 'FAIL'},
                {'id': 'ledger', 'type': 'LEDGER BLOCK', 'label': f"Block {block['block_number']}" if block else 'Not found', 'status': 'PASS' if chain_verification['valid'] and block else 'FAIL'},
                {'id': 'evidence', 'type': 'LEAKED FILE', 'label': evidence_path.name, 'status': 'PASS' if evidence_hash_match else 'FAIL'},
            ],
            'edges': [
                {'from': 'document', 'to': 'recipient'}, {'from': 'recipient', 'to': 'session'}, {'from': 'session', 'to': 'watermark'},
                {'from': 'watermark', 'to': 'event'}, {'from': 'event', 'to': 'signature'}, {'from': 'signature', 'to': 'ledger'}, {'from': 'ledger', 'to': 'evidence'},
            ],
        },
        'timeline': [
            {'label': 'Document registered', 'timestamp': document.get('created_at') if document else None, 'status': 'PASS'},
            {'label': 'Decryption event created', 'timestamp': event.get('timestamp'), 'status': 'PASS'},
            {'label': 'Watermark extracted', 'timestamp': event.get('timestamp'), 'status': 'PASS' if watermark_valid else 'FAIL'},
            {'label': 'Ledger verified', 'timestamp': event.get('timestamp'), 'status': 'PASS' if chain_verification['valid'] else 'FAIL'},
            {'label': 'Forensic analysis completed', 'timestamp': datetime.now(timezone.utc).isoformat(), 'status': 'PASS' if attribution_confirmed else 'FAIL'},
        ],
    }
    AuditService.record('FORENSIC_ANALYSIS', actor_id=user['user_id'], subject_id=event_id, outcome='SUCCESS' if attribution_confirmed else 'FAILURE')
    ForensicCaseService.create_case(case)
    return case


@router.post('/forensics/analyze-upload')
async def analyze_upload(file: UploadFile = File(...), user: dict = Depends(require_roles('ADMIN', 'FORENSIC_INVESTIGATOR'))):
    if not file.filename:
        raise HTTPException(status_code=400, detail='Evidence file is required')
    evidence_dir = Path(__file__).resolve().parents[2] / 'storage' / 'evidence'
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / Path(file.filename).name
    data = await file.read()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail='Evidence file exceeds the 50 MB limit')
    target.write_bytes(data)
    return analyze(AnalyzeRequest(document_path=str(target)), user)


@router.post('/forensics/simulate')
async def simulate_attack(mode: str, file: UploadFile = File(...), user: dict = Depends(require_roles('ADMIN', 'FORENSIC_INVESTIGATOR'))):
    if os.environ.get('TRACESEAL_ENABLE_SIMULATION', '').lower() not in {'1', 'true', 'yes'}:
        raise HTTPException(status_code=403, detail='Attack simulation is disabled')
    if mode not in {'modify_document', 'unrelated_document'}:
        raise HTTPException(status_code=400, detail='Unsupported simulation mode')
    evidence_dir = Path(__file__).resolve().parents[2] / 'storage' / 'evidence'
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / f'simulation-{datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")}.bin'
    data = await file.read()
    if mode == 'modify_document' and data:
        mutated = bytearray(data)
        mutated[len(mutated) // 2] ^= 0x01
        data = bytes(mutated)
    target.write_bytes(data)
    AuditService.record('ATTACK_SIMULATION', actor_id=user['user_id'], subject_id=target.name, details={'mode': mode})
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


@router.get('/forensics/cases/{case_id}/report.pdf')
def report_pdf(case_id: str, _: dict = Depends(current_user)):
    case = ForensicCaseService.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail='Case not found')
    import fitz
    report_dir = Path(__file__).resolve().parents[2] / 'storage' / 'reports'
    report_dir.mkdir(parents=True, exist_ok=True)
    target = report_dir / f'{case_id}.pdf'
    recipient = case.get('recipient') or {}
    document = case.get('document') or {}
    block = case.get('block') or {}
    lines = [
        'TRACESEAL FORENSIC EVIDENCE REPORT',
        f"Status: {case.get('verification_status', 'NOT VERIFIED')}",
        f"Case ID: {case_id}",
        f"Evidence: {case.get('evidence_filename', 'unknown')}",
        f"Evidence SHA3-256: {case.get('evidence_sha3_256', 'unknown')}",
        '',
        'ATTRIBUTION',
        f"Recipient: {recipient.get('display_name', 'unknown')} ({recipient.get('recipient_id', 'unknown')})",
        f"Document: {document.get('name', 'unknown')} ({document.get('document_id', 'unknown')})",
        f"Session: {case.get('session_id', 'unknown')}",
        f"Watermark: {case.get('watermark_id', 'unknown')}",
        f"Timestamp: {case.get('timestamp', 'unknown')}",
        '',
        'VERIFICATION',
        f"Watermark valid: {case.get('watermark_valid', False)}",
        f"Record hash valid: {case.get('record_hash_valid', False)}",
        f"Signature valid: {case.get('signature_valid', False)}",
        f"Document hash match: {case.get('document_hash_match', False)}",
        f"Ledger match: {case.get('ledger_match', False)}",
        f"Ledger chain valid: {case.get('chain_valid', False)}",
        '',
        'LEDGER EVIDENCE',
        f"Event ID: {case.get('event_id', 'unknown')}",
        f"Block: {block.get('block_number', 'unknown')}",
        f"Record hash: {block.get('record_hash', 'unknown')}",
        f"Previous block hash: {block.get('previous_hash', 'unknown')}",
        f"Block hash: {block.get('block_hash', 'unknown')}",
        f"Public key fingerprint: {recipient.get('public_key_fingerprint', 'unknown')}",
    ]
    pdf = fitz.open()
    page = pdf.new_page(width=595, height=842)
    page.insert_textbox(fitz.Rect(48, 48, 547, 790), '\n'.join(lines), fontsize=10, lineheight=1.45, fontname='helv')
    pdf.save(str(target))
    pdf.close()
    return FileResponse(target, media_type='application/pdf', filename=f'TraceSeal-{case_id}.pdf')


@router.post('/ledger/verify')
def verify_ledger(payload: VerifyLedgerRequest, _: dict = Depends(require_roles('ADMIN', 'SENDER', 'FORENSIC_INVESTIGATOR'))):
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
def get_event(event_id: str, _: dict = Depends(require_roles('ADMIN', 'SENDER', 'FORENSIC_INVESTIGATOR'))):
    event = DecryptionService.get_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail='Event not found')
    return event


@router.get('/events')
def list_events(_: dict = Depends(require_roles('ADMIN', 'SENDER', 'FORENSIC_INVESTIGATOR'))):
    return DecryptionService.list_events()


@router.post('/forensics/verify/{event_id}')
def verify_event(event_id: str, _: dict = Depends(require_roles('ADMIN', 'FORENSIC_INVESTIGATOR'))):
    result = DecryptionService.verify_event(event_id)
    if result.get('reason') == 'event_not_found':
        raise HTTPException(status_code=404, detail='Event not found')
    return result


@router.get('/watermarks/{watermark_id}')
def get_watermark(watermark_id: str, _: dict = Depends(require_roles('ADMIN', 'SENDER', 'FORENSIC_INVESTIGATOR'))):
    watermark = WatermarkService.get_watermark(watermark_id)
    if watermark is None:
        raise HTTPException(status_code=404, detail='Watermark not found')
    return watermark


@router.get('/ledger/watermark/{watermark_id}')
def get_ledger_by_watermark(watermark_id: str, _: dict = Depends(require_roles('ADMIN', 'SENDER', 'FORENSIC_INVESTIGATOR'))):
    rows = LedgerService.find_by_watermark(watermark_id)
    return {'watermark_id': watermark_id, 'matches': rows}


@router.get('/ledger/event/{event_id}')
def get_ledger_by_event(event_id: str, _: dict = Depends(require_roles('ADMIN', 'SENDER', 'FORENSIC_INVESTIGATOR'))):
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
