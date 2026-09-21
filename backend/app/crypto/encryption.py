from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError('AES key must be 32 bytes')
    if len(nonce) != 12:
        raise ValueError('AES nonce must be 12 bytes')
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return ciphertext[:-16], ciphertext[-16:]


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError('AES key must be 32 bytes')
    if len(nonce) != 12:
        raise ValueError('AES nonce must be 12 bytes')
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext + tag, None)


def generate_aes_key() -> bytes:
    return os.urandom(32)


def generate_nonce() -> bytes:
    return os.urandom(12)
