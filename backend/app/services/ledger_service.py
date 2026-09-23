from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.crypto.hashing import sha3_256_hex


class LedgerService:
    DATA_PATH = Path(__file__).resolve().parents[2] / "ledger_data" / "chain.json"
    VALIDATORS = ('NODE-01', 'NODE-02', 'NODE-03')

    @staticmethod
    def _initial_chain() -> list[dict[str, Any]]:
        genesis = {
            "block_number": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": "0" * 64,
            "transactions": [],
            "transaction_root": "0" * 64,
            "block_hash": "0" * 64,
        }
        genesis["block_hash"] = sha3_256_hex(
            f"{genesis['block_number']}|{genesis['timestamp']}|{genesis['previous_hash']}|{genesis['transaction_root']}"
        )
        return [genesis]

    @staticmethod
    def _load_chain() -> list[dict[str, Any]]:
        if not LedgerService.DATA_PATH.exists():
            chain = LedgerService._initial_chain()
            LedgerService.DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
            LedgerService.DATA_PATH.write_text(json.dumps(chain, indent=2), encoding='utf-8')
            return chain
        with LedgerService.DATA_PATH.open('r', encoding='utf-8') as handle:
            try:
                data = json.load(handle)
            except json.JSONDecodeError:
                data = LedgerService._initial_chain()
        return data if isinstance(data, list) else LedgerService._initial_chain()

    @staticmethod
    def _save_chain(chain: list[dict[str, Any]]) -> None:
        LedgerService.DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        LedgerService.DATA_PATH.write_text(json.dumps(chain, indent=2), encoding='utf-8')

    @staticmethod
    def create_genesis_block() -> dict[str, Any]:
        chain = LedgerService._load_chain()
        if len(chain) == 0 or chain[0]['block_number'] != 0:
            chain = LedgerService._initial_chain()
            LedgerService._save_chain(chain)
        return chain[0]

    @staticmethod
    def add_transaction(tx: dict[str, Any]) -> dict[str, Any]:
        chain = LedgerService._load_chain()
        prev = chain[-1]
        block = {
            "block_number": len(chain),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": prev['block_hash'],
            "transactions": [tx],
            "transaction_root": sha3_256_hex(json.dumps(tx, sort_keys=True, separators=(",", ":"))),
            "block_hash": "",
        }
        block['block_hash'] = sha3_256_hex(
            f"{block['block_number']}|{block['timestamp']}|{block['previous_hash']}|{block['transaction_root']}"
        )
        chain.append(block)
        LedgerService._save_chain(chain)
        return block

    @staticmethod
    def add_block(tx: dict[str, Any]) -> dict[str, Any]:
        return LedgerService.add_transaction(tx)

    @staticmethod
    def list_blocks() -> list[dict[str, Any]]:
        return LedgerService._load_chain()

    @staticmethod
    def get_block(block_number: int) -> dict[str, Any] | None:
        chain = LedgerService._load_chain()
        for block in chain:
            if block["block_number"] == block_number:
                return block
        return None

    @staticmethod
    def validate_chain() -> bool:
        return LedgerService.verify_chain()['valid']

    @staticmethod
    def verify_chain() -> dict[str, Any]:
        chain = LedgerService._load_chain()
        if not chain:
            return {'valid': False, 'checked_blocks': 0, 'failed_block': None, 'reason': 'empty_chain'}
        previous_hash = '0' * 64
        for index, block in enumerate(chain):
            if block.get('block_number') != index:
                return {'valid': False, 'checked_blocks': index, 'failed_block': index, 'reason': 'block_number_mismatch'}
            if index == 0 and block.get('previous_hash') != '0' * 64:
                return {'valid': False, 'checked_blocks': index, 'failed_block': index, 'reason': 'genesis_previous_hash_mismatch'}
            if index > 0 and block.get('previous_hash') != previous_hash:
                return {'valid': False, 'checked_blocks': index, 'failed_block': index, 'reason': 'previous_hash_mismatch'}
            transactions = block.get('transactions', [])
            if len(transactions) == 0:
                expected_root = '0' * 64
            elif len(transactions) == 1:
                expected_root = sha3_256_hex(json.dumps(transactions[0], sort_keys=True, separators=(",", ":")))
            else:
                expected_root = sha3_256_hex(json.dumps(transactions, sort_keys=True, separators=(",", ":")))
            if block.get('transaction_root') != expected_root:
                return {'valid': False, 'checked_blocks': index, 'failed_block': index, 'reason': 'transaction_root_mismatch'}
            expected = sha3_256_hex(
                f"{block['block_number']}|{block['timestamp']}|{block['previous_hash']}|{block['transaction_root']}"
            )
            if block.get('block_hash') != expected:
                return {'valid': False, 'checked_blocks': index, 'failed_block': index, 'reason': 'block_hash_mismatch'}
            previous_hash = block.get('block_hash', '')
        return {'valid': True, 'checked_blocks': len(chain), 'failed_block': None, 'reason': None}

    @staticmethod
    def _detect_tampering(block: dict[str, Any], chain: list[dict[str, Any]]) -> bool:
        current = block.get('block_hash', '')
        expected = sha3_256_hex(
            f"{block['block_number']}|{block['timestamp']}|{block['previous_hash']}|{block['transaction_root']}"
        )
        return current != expected

    @staticmethod
    def find_by_watermark(watermark_id: str) -> list[dict[str, Any]]:
        chain = LedgerService._load_chain()
        matches = []
        for block in chain:
            for tx in block.get('transactions', []):
                if tx.get('watermark_id') == watermark_id:
                    matches.append(tx)
        return matches

    @staticmethod
    def find_by_event_id(event_id: str) -> list[dict[str, Any]]:
        chain = LedgerService._load_chain()
        matches = []
        for block in chain:
            for tx in block.get('transactions', []):
                if tx.get('event_id') == event_id:
                    matches.append(tx)
        return matches

    @staticmethod
    def find_block_by_event_id(event_id: str) -> dict[str, Any] | None:
        for block in LedgerService._load_chain():
            if any(tx.get('event_id') == event_id for tx in block.get('transactions', [])):
                return block
        return None

    @staticmethod
    def find_block_by_watermark(watermark_id: str) -> dict[str, Any] | None:
        for block in LedgerService._load_chain():
            if any(tx.get('watermark_id') == watermark_id for tx in block.get('transactions', [])):
                return block
        return None

    @staticmethod
    def get_transaction(tx_id: str) -> dict[str, Any] | None:
        chain = LedgerService._load_chain()
        for block in chain:
            for tx in block.get('transactions', []):
                if tx.get('event_id') == tx_id or tx.get('tx_id') == tx_id:
                    return tx
        return None

    @staticmethod
    def quorum_status() -> dict[str, Any]:
        valid = LedgerService.validate_chain()
        approvals = len(LedgerService.VALIDATORS) if valid else 0
        return {
            'validators': list(LedgerService.VALIDATORS),
            'required': 2,
            'approvals': approvals,
            'committed': approvals >= 2,
            'chain_valid': valid,
        }
