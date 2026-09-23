from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.services.ledger_service import LedgerService
from app.api.auth import current_user

router = APIRouter(tags=['ledger'])


@router.get('/ledger/blocks')
def list_blocks(_: dict = Depends(current_user)):
    return LedgerService.list_blocks()


@router.get('/ledger/blocks/{block_number}')
def get_block(block_number: int, _: dict = Depends(current_user)):
    block = LedgerService.get_block(block_number)
    if block is None:
        raise HTTPException(status_code=404, detail='Block not found')
    return block


@router.get('/ledger/validate')
def validate_ledger(_: dict = Depends(current_user)):
    verification = LedgerService.verify_chain()
    return {'valid': verification['valid'], 'reason': verification.get('reason'), 'failed_block': verification.get('failed_block'), 'quorum': LedgerService.quorum_status()}


@router.get('/ledger/quorum')
def ledger_quorum(_: dict = Depends(current_user)):
    return LedgerService.quorum_status()
