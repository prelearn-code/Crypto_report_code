from __future__ import annotations

from dataclasses import dataclass

from common.types import SmallLeftCiphertext, SmallORESecretKey, SmallRightCiphertext
from ore_small.compare import ore_small_compare
from ore_small.decrypt import ore_small_decrypt
from ore_small.encrypt_left import ore_small_encrypt_left
from ore_small.encrypt_right import ore_small_encrypt_right
from ore_small.setup import ore_small_setup


@dataclass
class SmallDomainORE:
    """Convenience wrapper for small-domain ORE APIs."""

    sk: SmallORESecretKey

    @classmethod
    def setup(cls, domain_size: int, key_bytes: int = 16) -> "SmallDomainORE":
        return cls(sk=ore_small_setup(domain_size=domain_size, key_bytes=key_bytes))

    def encrypt_left(self, x: int) -> SmallLeftCiphertext:
        return ore_small_encrypt_left(self.sk, x)

    def encrypt_right(self, y: int) -> SmallRightCiphertext:
        return ore_small_encrypt_right(self.sk, y)

    @staticmethod
    def compare(ct_l: SmallLeftCiphertext, ct_r: SmallRightCiphertext) -> int:
        return ore_small_compare(ct_l, ct_r)

    def decrypt(self, ct_r: SmallRightCiphertext) -> int:
        return ore_small_decrypt(self.sk, ct_r)
