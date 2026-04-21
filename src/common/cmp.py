from __future__ import annotations


def cmp3(x: int, y: int) -> int:
    """Return 0 if x == y, 1 if x < y, 2 if x > y."""

    if x == y:
        return 0
    if x < y:
        return 1
    return 2


def decode_cmp3(v: int) -> int:
    """Decode cmp3 code back to conventional cmp result in {0, -1, 1}."""

    if v == 0:
        return 0
    if v == 1:
        return -1
    if v == 2:
        return 1
    raise ValueError(f"Invalid cmp3 value: {v}")
