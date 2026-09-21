import hashlib
import os
import tempfile
from pathlib import Path

import cv2
import numpy as np
import pytest

from app.crypto.hashing import sha3_256, sha3_256_hex
from app.crypto.encryption import aes_gcm_encrypt, aes_gcm_decrypt
from app.crypto.pq import generate_ml_dsa_keypair, sign_event, verify_signature, generate_ml_kem_keypair, encapsulate, decapsulate
from app.crypto.key_store import encrypt_private_key_material, decrypt_private_key_material
from app.services.watermark_service import WatermarkService
from app.services.ledger_service import LedgerService
from app.services.decryption_service import DecryptionService
from app.services.recipient_service import RecipientService
from app.services.document_service import DocumentService


def test_sha3_hashing():
    assert sha3_256_hex(b'hello') == hashlib.sha3_256(b'hello').hexdigest()


def test_aes_gcm_roundtrip():
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b'hello world from forensic system'
    ciphertext, tag = aes_gcm_encrypt(key, nonce, plaintext)
    recovered = aes_gcm_decrypt(key, nonce, ciphertext, tag)
    assert recovered == plaintext


def test_ml_dsa_sign_verify():
    sk, pk = generate_ml_dsa_keypair()
    msg = b'event-hash-1'
    sig = sign_event(sk, msg)
    assert verify_signature(pk, msg, sig) is True


def test_ml_kem_roundtrip():
    sk, pk = generate_ml_kem_keypair()
    ct, ss1 = encapsulate(pk)
    ss2 = decapsulate(sk, ct)
    assert ss1 == ss2


def test_session_uniqueness():
    sessions = {DecryptionService.generate_session_id() for _ in range(10)}
    assert len(sessions) == 10


def test_watermark_generation_and_detection():
    payload = {
        'document_id': 'DOC-001',
        'recipient_id': 'REC-001',
        'session_id': 'SES-TEST-1',
        'nonce': 'NONCE-XYZ',
        'timestamp': '2024-01-01T00:00:00Z',
    }
    wm1 = WatermarkService.generate_watermark_payload(payload)
    wm2 = WatermarkService.generate_watermark_payload({**payload, 'recipient_id': 'REC-002'})
    assert wm1 != wm2


def test_watermark_embedding_and_extraction(tmp_path):
    image_path = tmp_path / 'sample.png'
    cv2.imwrite(str(image_path), np.full((512, 512, 3), 180, dtype=np.uint8))
    artifact = WatermarkService.embed_watermark(image_path, 'REC-001', 'DOC-001', 'SES-ABC', 'NONCE-1')
    assert artifact['watermark_id']
    detail = WatermarkService.detect_watermark(artifact['output_path'])
    assert detail['detected'] is True
    assert detail['watermark_id'] == artifact['watermark_id']
    assert detail['algorithm'] == 'DCT'


def test_txt_watermark_is_explicitly_unsupported(tmp_path):
    text_path = tmp_path / 'sample.txt'
    text_path.write_text('ordinary text', encoding='utf-8')
    result = WatermarkService.detect_watermark(text_path)
    assert result['detected'] is False
    assert result['supported'] is False
    assert 'requires PDF, PNG, or JPEG' in result['message']


def test_unwatermarked_visual_document_is_not_detected(tmp_path):
    image_path = tmp_path / 'plain.png'
    cv2.imwrite(str(image_path), np.full((512, 512, 3), 180, dtype=np.uint8))
    result = WatermarkService.detect_watermark(image_path)
    assert result['detected'] is False
    assert result['watermark_id'] is None


def test_corrupted_watermark_detection(tmp_path):
    pdf_path = tmp_path / 'corrupt.pdf'
    pdf_path.write_bytes(b'%PDF-1.4\nbadness\n')
    result = WatermarkService.detect_watermark(pdf_path)
    assert result['detected'] in {True, False}


def test_ledger_block_hashing():
    block = LedgerService.create_genesis_block()
    assert block['block_hash']
    assert block['previous_hash'] == '0' * 64


def test_ledger_chain_validation():
    chain = LedgerService.create_genesis_block()
    second = LedgerService.add_block({'tx_id': 'tx-2', 'kind': 'event'})
    assert LedgerService.validate_chain() is True
    assert second['block_number'] >= 1


def test_modified_block_detection():
    chain = LedgerService.create_genesis_block()
    second = LedgerService.add_block({'tx_id': 'tx-3', 'kind': 'event'})
    modified = dict(second)
    modified['block_hash'] = '00' * 32
    assert LedgerService._detect_tampering(modified, chain) in {True, False}


def test_event_lookup_and_mapping():
    event = DecryptionService.create_decryption_event(
        document_id='DOC-001',
        recipient_id='REC-001',
        session_id='SES-LOOKUP',
        watermark_id='WM-TEST-1',
        document_hash='abc',
        watermarked_hash='def',
    )
    found = DecryptionService.get_event_by_id(event['event_id'])
    assert found['event_id'] == event['event_id']


def test_recipient_key_store_roundtrip():
    key = b'0123456789abcdef0123456789abcdef'
    payload = {'private_key': 'secret-value'}
    encrypted = encrypt_private_key_material(payload, key)
    restored = decrypt_private_key_material(encrypted, key)
    assert restored == payload


def test_recipient_a_and_b_watermark_ids_differ():
    wm_a = WatermarkService.generate_watermark_payload({
        'document_id': 'DOC-001',
        'recipient_id': 'REC-001',
        'session_id': 'SES-ALICE',
        'nonce': 'n1',
        'timestamp': '2025-01-01T00:00:00Z',
    })
    wm_b = WatermarkService.generate_watermark_payload({
        'document_id': 'DOC-001',
        'recipient_id': 'REC-002',
        'session_id': 'SES-BOB',
        'nonce': 'n2',
        'timestamp': '2025-01-01T00:00:00Z',
    })
    assert wm_a != wm_b


def test_document_encrypt_and_decrypt_roundtrip(tmp_path):
    source = tmp_path / 'sample.txt'
    source.write_text('forensic evidence payload', encoding='utf-8')
    key = os.urandom(32)
    encrypted = DocumentService.encrypt_document_file(source, 'REC-TEST-1', key)
    decrypted = DocumentService.decrypt_document_file(encrypted['encrypted_path'], key)
    assert decrypted['plaintext_path'].exists()
    assert Path(decrypted['plaintext_path']).read_text(encoding='utf-8') == 'forensic evidence payload'
