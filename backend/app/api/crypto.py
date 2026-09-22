from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.crypto.pq import generate_ml_dsa_keypair, generate_ml_kem_keypair, sign_event, verify_signature, encapsulate, decapsulate
from app.api.auth import require_roles

router = APIRouter(tags=['crypto'])


class SignRequest(BaseModel):
    private_key: str
    message: str


@router.get('/crypto/test')
def crypto_test(_: dict = Depends(require_roles('ADMIN'))):
    dsa_pk, dsa_sk = generate_ml_dsa_keypair()
    kem_pk, kem_sk = generate_ml_kem_keypair()
    return {'dsa_public': dsa_pk, 'kem_public': kem_pk, 'algorithms': ['ML-DSA-65', 'ML-KEM-768']}


@router.post('/crypto/sign')
def sign(req: SignRequest, _: dict = Depends(require_roles('ADMIN'))):
    try:
        signature = sign_event(req.private_key, req.message.encode('utf-8'))
        return {'signature': signature}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post('/crypto/verify')
def verify(payload: dict, _: dict = Depends(require_roles('ADMIN', 'FORENSIC_INVESTIGATOR'))):
    public_key = payload.get('public_key')
    message = payload.get('message', '')
    signature = payload.get('signature', '')
    if not public_key or not signature:
        raise HTTPException(status_code=400, detail='public_key and signature are required')
    return {'valid': verify_signature(public_key, message.encode('utf-8'), signature)}


@router.post('/crypto/encapsulate')
def encapsulate_key(payload: dict, _: dict = Depends(require_roles('ADMIN', 'SENDER'))):
    public_key = payload.get('public_key')
    if not public_key:
        raise HTTPException(status_code=400, detail='public_key is required')
    ciphertext, shared_secret = encapsulate(public_key)
    return {'ciphertext': ciphertext, 'shared_secret': shared_secret.hex()}


@router.post('/crypto/decapsulate')
def decapsulate_key(payload: dict, _: dict = Depends(require_roles('ADMIN'))):
    private_key = payload.get('private_key')
    ciphertext = payload.get('ciphertext')
    if not private_key or not ciphertext:
        raise HTTPException(status_code=400, detail='private_key and ciphertext are required')
    shared_secret = decapsulate(private_key, ciphertext)
    return {'shared_secret': shared_secret.hex()}
