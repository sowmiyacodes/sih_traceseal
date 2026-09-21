import hashlib
from typing import Union


def sha3_256(data: Union[bytes, str]) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha3_256(data).digest()


def sha3_256_hex(data: Union[bytes, str]) -> str:
    return sha3_256(data).hex()
