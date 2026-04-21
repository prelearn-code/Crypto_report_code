from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SmallORESecretKey:
    """Secret key for the small-domain ORE construction."""

    prf_key: bytes
    prp_seed: bytes
    domain_size: int


@dataclass(frozen=True)
class SmallLeftCiphertext:
    """Left ciphertext (query token)."""

    key_material: bytes
    h: int


@dataclass(frozen=True)
class SmallRightCiphertext:
    """Right ciphertext (stored encrypted value)."""

    nonce: bytes
    v: tuple[int, ...]
