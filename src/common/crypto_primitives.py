from __future__ import annotations

import hashlib
import hmac
import os


def prf_sha256(key: bytes, data: bytes, out_len: int = 16) -> bytes:
    """HMAC-SHA256 PRF truncated to out_len bytes."""

    digest = hmac.new(key, data, hashlib.sha256).digest()
    return digest[:out_len]


def prf_aes_block(key: bytes, block16: bytes) -> bytes:
    """Placeholder AES-like PRF API; uses HMAC-SHA256 for teaching fallback."""

    if len(block16) != 16:
        raise ValueError("block16 must be 16 bytes")
    return prf_sha256(key, block16, out_len=16)


def hash_to_z3(key_material: bytes, nonce: bytes) -> int:
    """Hash key material and nonce to Z_3."""

    d = hashlib.sha256(key_material + b"|" + nonce).digest()
    return int.from_bytes(d, "big") % 3


def hash_to_bit(key_material: bytes, nonce: bytes) -> int:
    """Hash key material and nonce to {0, 1}."""

    d = hashlib.sha256(key_material + b"|" + nonce).digest()
    return d[0] & 1


def random_nonce(nbytes: int = 16) -> bytes:
    """Generate random nonce."""

    return os.urandom(nbytes)
