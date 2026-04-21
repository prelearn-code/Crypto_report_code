from __future__ import annotations

from common.cmp import cmp3
from common.crypto_primitives import hash_to_z3, prf_sha256, random_nonce
from common.encoding import encode_int
from common.prp_small_domain import SmallDomainPRP
from common.types import SmallORESecretKey, SmallRightCiphertext


def ore_small_encrypt_right(sk: SmallORESecretKey, y: int) -> SmallRightCiphertext:
    """ct_R = (r, v_0,...,v_{N-1}) over permuted domain indexes."""

    if not (0 <= y < sk.domain_size):
        raise ValueError("y out of range")

    prp = SmallDomainPRP(sk.prp_seed, sk.domain_size)
    r = random_nonce(16)
    values: list[int] = []

    for i in range(sk.domain_size):
        candidate = prp.invert(i)
        cmp_val = cmp3(candidate, y)
        fk_i = prf_sha256(sk.prf_key, encode_int(i, width=4), out_len=16)
        mask = hash_to_z3(fk_i, r)
        values.append((cmp_val + mask) % 3)

    return SmallRightCiphertext(nonce=r, v=tuple(values))
