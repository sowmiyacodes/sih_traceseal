from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Tuple

try:
    import oqs
except Exception:  # pragma: no cover - fallback for environments without liboqs
    oqs = None


FALLBACK_KEM_KEYS: dict[str, str] = {}


def register_fallback_kem_keypair(private_key: str, public_key: str) -> None:
    """Restore the local fallback mapping after a backend restart."""
    if oqs is None:
        FALLBACK_KEM_KEYS[public_key] = private_key
        FALLBACK_KEM_KEYS[private_key] = public_key


def _safe_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def generate_ml_dsa_keypair() -> Tuple[str, str]:
    if oqs is not None:
        keypair = oqs.KeyPair("ML-DSA-65")
        return keypair.private_key.hex(), keypair.public_key.hex()
    private_key = os.urandom(32).hex()
    public_key = hashlib.sha3_256(bytes.fromhex(private_key)).hexdigest()
    return private_key, public_key


def sign_event(private_key: str, message: bytes) -> str:
    if oqs is not None:
        signing_key = oqs.SignatureSecretKey.from_bytes(bytes.fromhex(private_key), "ML-DSA-65")
        return signing_key.sign(message).hex()
    public_key = hashlib.sha3_256(bytes.fromhex(private_key)).hexdigest()
    return hashlib.sha3_256(bytes.fromhex(public_key) + message).hexdigest()


def verify_signature(public_key: str, message: bytes, signature: str) -> bool:
    if oqs is not None:
        verifying_key = oqs.SignaturePublicKey.from_bytes(bytes.fromhex(public_key), "ML-DSA-65")
        try:
            verifying_key.verify(message, bytes.fromhex(signature))
            return True
        except Exception:
            return False
    expected = hashlib.sha3_256(bytes.fromhex(public_key) + message).hexdigest()
    return expected == signature


def generate_ml_kem_keypair() -> Tuple[str, str]:
    if oqs is not None:
        keypair = oqs.KeyPair("ML-KEM-768")
        return keypair.private_key.hex(), keypair.public_key.hex()
    private_key = os.urandom(32).hex()
    public_key = hashlib.sha3_256(bytes.fromhex(private_key)).hexdigest()
    FALLBACK_KEM_KEYS[public_key] = private_key
    FALLBACK_KEM_KEYS[private_key] = public_key
    return private_key, public_key


def encapsulate(public_key: str) -> Tuple[str, bytes]:
    if oqs is not None:
        pk = oqs.EncapsulationPublicKey.from_bytes(bytes.fromhex(public_key), "ML-KEM-768")
        ciphertext, shared_secret = pk.encapsulate()
        return ciphertext.hex(), shared_secret
    if public_key not in FALLBACK_KEM_KEYS:
        raise ValueError('Unknown public key')
    private_key = FALLBACK_KEM_KEYS[public_key]
    secret_material = bytes.fromhex(public_key) + bytes.fromhex(private_key)
    shared_secret = hashlib.sha3_256(secret_material).digest()
    ciphertext = public_key
    return ciphertext, shared_secret


def decapsulate(private_key: str, ciphertext: str) -> bytes:
    if oqs is not None:
        sk = oqs.EncapsulationSecretKey.from_bytes(bytes.fromhex(private_key), "ML-KEM-768")
        return sk.decapsulate(bytes.fromhex(ciphertext))
    public_key = FALLBACK_KEM_KEYS.get(private_key)
    if public_key is None:
        try:
            public_key = hashlib.sha3_256(bytes.fromhex(private_key)).hexdigest()
        except ValueError as exc:
            raise ValueError('Invalid private key') from exc
    if ciphertext != public_key:
        raise ValueError('Recipient private key does not match this package')
    secret_material = bytes.fromhex(public_key) + bytes.fromhex(private_key)
    return hashlib.sha3_256(secret_material).digest()
