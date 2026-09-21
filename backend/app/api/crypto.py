from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.crypto.pq import generate_ml_dsa_keypair, generate_ml_kem_keypair, sign_event, verify_signature, encapsulate, decapsulate

router = APIRouter(tags=['crypto'])


class SignRequest(BaseModel):
    private_key: str
    message: str


@router.get('/crypto/test')
def crypto_test():
    dsa_pk, dsa_sk = generate_ml_dsa_keypair()
    kem_pk, kem_sk = generate_ml_kem_keypair()
    return {'dsa_public': dsa_pk, 'dsa_private': dsa_sk[:8], 'kem_public': kem_pk, 'kem_private': kem_sk[:8]}


@router.post('/crypto/sign')
def sign(req: SignRequest):
    try:
        signature = sign_event(req.private_key, req.message.encode('utf-8'))
        return {'signature': signature}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post('/crypto/verify')
def verify(payload: dict):
    public_key = payload.get('public_key')
    message = payload.get('message', '')
    signature = payload.get('signature', '')
    if not public_key or not signature:
        raise HTTPException(status_code=400, detail='public_key and signature are required')
    return {'valid': verify_signature(public_key, message.encode('utf-8'), signature)}


@router.post('/crypto/encapsulate')
def encapsulate_key(payload: dict):
    public_key = payload.get('public_key')
    if not public_key:
        raise HTTPException(status_code=400, detail='public_key is required')
    ciphertext, shared_secret = encapsulate(public_key)
    return {'ciphertext': ciphertext, 'shared_secret': shared_secret.hex()}


@router.post('/crypto/decapsulate')
def decapsulate_key(payload: dict):
    private_key = payload.get('private_key')
    ciphertext = payload.get('ciphertext')
    if not private_key or not ciphertext:
        raise HTTPException(status_code=400, detail='private_key and ciphertext are required')
    shared_secret = decapsulate(private_key, ciphertext)
    return {'shared_secret': shared_secret.hex()}
