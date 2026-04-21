from __future__ import annotations

from common.types import SmallORESecretKey, SmallRightCiphertext
from ore_small.compare import ore_small_compare
from ore_small.encrypt_left import ore_small_encrypt_left


def ore_small_decrypt(sk: SmallORESecretKey, ct_r: SmallRightCiphertext) -> int:
    """Recover plaintext via linear scan and equality test."""

    for x in range(sk.domain_size):
        ct_l = ore_small_encrypt_left(sk, x)
        if ore_small_compare(ct_l, ct_r) == 0:
            return x
    raise ValueError("no plaintext found")
