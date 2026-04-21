from __future__ import annotations



def encode_int(x: int, width: int | None = None) -> bytes:
    """Deterministically encode a non-negative integer."""

    if x < 0:
        raise ValueError("x must be non-negative")
    if width is None:
        width = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(width, "big")


def encode_blocks(blocks: list[int], block_width: int) -> bytes:
    """Encode block list with fixed byte-width per block."""

    if block_width <= 0:
        raise ValueError("block_width must be positive")
    return b"".join(encode_int(b, width=block_width) for b in blocks)


def split_blocks_u32(x: int, block_bits: int = 8) -> list[int]:
    """Split unsigned 32-bit int into big-endian fixed-width blocks."""

    if not (0 <= x <= 0xFFFFFFFF):
        raise ValueError("x must be a 32-bit unsigned integer")
    if 32 % block_bits != 0:
        raise ValueError("block_bits must divide 32")
    mask = (1 << block_bits) - 1
    n = 32 // block_bits
    out = []
    for i in reversed(range(n)):
        out.append((x >> (i * block_bits)) & mask)
    return out


def join_blocks(blocks: list[int], block_bits: int = 8) -> int:
    """Join fixed-width blocks into an integer."""

    if block_bits <= 0:
        raise ValueError("block_bits must be positive")
    max_block = (1 << block_bits) - 1
    value = 0
    for b in blocks:
        if not (0 <= b <= max_block):
            raise ValueError("block out of range")
        value = (value << block_bits) | b
    return value
