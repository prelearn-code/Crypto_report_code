from __future__ import annotations

import random


class SmallDomainPRP:
    """Seeded Fisher-Yates permutation over [0, domain_size-1]."""

    def __init__(self, seed: bytes, domain_size: int):
        if domain_size <= 0:
            raise ValueError("domain_size must be positive")
        self.domain_size = domain_size
        self._perm = list(range(domain_size))
        rng = random.Random(int.from_bytes(seed, "big"))
        for i in range(domain_size - 1, 0, -1):
            j = rng.randint(0, i)
            self._perm[i], self._perm[j] = self._perm[j], self._perm[i]
        self._inv = [0] * domain_size
        for i, p in enumerate(self._perm):
            self._inv[p] = i

    def permute(self, x: int) -> int:
        if not (0 <= x < self.domain_size):
            raise ValueError("x out of range")
        return self._perm[x]

    def invert(self, y: int) -> int:
        if not (0 <= y < self.domain_size):
            raise ValueError("y out of range")
        return self._inv[y]
