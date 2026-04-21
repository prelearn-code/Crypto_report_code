from __future__ import annotations

import random

from common.cmp import cmp3
from ore_small.scheme import SmallDomainORE


def test_compare_matches_plain_cmp3_random_pairs() -> None:
    domain_size = 64
    ore = SmallDomainORE.setup(domain_size=domain_size, key_bytes=16)

    for _ in range(500):
        x = random.randrange(domain_size)
        y = random.randrange(domain_size)
        ct_l = ore.encrypt_left(x)
        ct_r = ore.encrypt_right(y)
        assert ore.compare(ct_l, ct_r) == cmp3(x, y)


def test_decrypt_recovers_all_values_in_domain() -> None:
    domain_size = 32
    ore = SmallDomainORE.setup(domain_size=domain_size, key_bytes=16)

    for y in range(domain_size):
        ct_r = ore.encrypt_right(y)
        assert ore.decrypt(ct_r) == y


def test_compare_full_cross_product_small_domain() -> None:
    domain_size = 16
    ore = SmallDomainORE.setup(domain_size=domain_size, key_bytes=16)

    for x in range(domain_size):
        ct_l = ore.encrypt_left(x)
        for y in range(domain_size):
            ct_r = ore.encrypt_right(y)
            assert ore.compare(ct_l, ct_r) == cmp3(x, y)
