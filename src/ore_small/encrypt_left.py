from __future__ import annotations

from common.crypto_primitives import prf_sha256
from common.encoding import encode_int
from common.prp_small_domain import SmallDomainPRP
from common.types import SmallLeftCiphertext, SmallORESecretKey


def ore_small_encrypt_left(sk: SmallORESecretKey, x: int) -> SmallLeftCiphertext:
    """ct_L = (F(k, pi(x)), pi(x))."""

    prp = SmallDomainPRP(sk.prp_seed, sk.domain_size)
    h = prp.permute(x)
    key_material = prf_sha256(sk.prf_key, encode_int(h, width=4), out_len=16)
    return SmallLeftCiphertext(key_material=key_material, h=h)
