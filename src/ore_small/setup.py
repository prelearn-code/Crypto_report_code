from __future__ import annotations

import os

from common.types import SmallORESecretKey


def ore_small_setup(domain_size: int, key_bytes: int = 16) -> SmallORESecretKey:
    """Generate secret key for small-domain ORE."""

    if domain_size <= 0:
        raise ValueError("domain_size must be positive")
    if key_bytes <= 0:
        raise ValueError("key_bytes must be positive")
    return SmallORESecretKey(
        prf_key=os.urandom(key_bytes),
        prp_seed=os.urandom(key_bytes),
        domain_size=domain_size,
    )
