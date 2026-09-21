from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.fernet import Fernet


def _get_fernet() -> Fernet:
    key_material = os.environ.get('KEYSTORE_PASSWORD', 'local-dev-keystore-passphrase').encode()
    hashed = base64.urlsafe_b64encode(key_material[:32].ljust(32, b'0'))
    return Fernet(hashed)


def encrypt_private_key_material(data: Any, password_key: bytes | None = None) -> str:
    payload = json.dumps(data, sort_keys=True).encode('utf-8')
    if password_key is None:
        password_key = os.environ.get('KEYSTORE_PASSWORD', 'local-dev-keystore-passphrase').encode()
    if isinstance(password_key, str):
        password_key = password_key.encode()
    base = base64.urlsafe_b64encode(password_key[:32].ljust(32, b'0'))
    return Fernet(base).encrypt(payload).decode('utf-8')


def decrypt_private_key_material(token: str, password_key: bytes | None = None) -> dict:
    if password_key is None:
        password_key = os.environ.get('KEYSTORE_PASSWORD', 'local-dev-keystore-passphrase').encode()
    if isinstance(password_key, str):
        password_key = password_key.encode()
    base = base64.urlsafe_b64encode(password_key[:32].ljust(32, b'0'))
    return json.loads(Fernet(base).decrypt(token.encode('utf-8')).decode('utf-8'))
