from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services.ledger_service import LedgerService

router = APIRouter(tags=['ledger'])


@router.get('/ledger/blocks')
def list_blocks():
    return LedgerService.list_blocks()


@router.get('/ledger/blocks/{block_number}')
def get_block(block_number: int):
    block = LedgerService.get_block(block_number)
    if block is None:
        raise HTTPException(status_code=404, detail='Block not found')
    return block


@router.get('/ledger/validate')
def validate_ledger():
    return {'valid': LedgerService.validate_chain()}
