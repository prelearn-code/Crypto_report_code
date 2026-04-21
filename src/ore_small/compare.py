from __future__ import annotations

from common.crypto_primitives import hash_to_z3
from common.types import SmallLeftCiphertext, SmallRightCiphertext


def ore_small_compare(ct_l: SmallLeftCiphertext, ct_r: SmallRightCiphertext) -> int:
    """Return cmp3 code by unmasking index selected by left ciphertext."""

    if not (0 <= ct_l.h < len(ct_r.v)):
        raise ValueError("left ciphertext index out of range")
    value = ct_r.v[ct_l.h]
    mask = hash_to_z3(ct_l.key_material, ct_r.nonce)
    return (value - mask) % 3
