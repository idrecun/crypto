"""Byte, bit, and block conversion helpers."""


def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    assert len(bits) % 8 == 0
    assert all(bit in (0, 1) for bit in bits)
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        byte_array.append(byte)
    return bytes(byte_array)


def xor(left: bytes, right: bytes) -> bytes:
    assert len(left) == len(right)
    return bytes(a ^ b for a, b in zip(left, right))


def split_blocks(data: bytes, block_size: int) -> list[bytes]:
    assert block_size > 0
    assert len(data) % block_size == 0
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def bytes_to_blocks(data: bytes, block_size: int) -> list[bytes]:
    """Split bytes into fixed-size blocks.

    This helper is strict: the input length must already be divisible by
    ``block_size``.
    """

    return split_blocks(data, block_size)


def blocks_to_bytes(blocks: list[bytes]) -> bytes:
    if not blocks:
        return b""
    block_size = len(blocks[0])
    assert block_size > 0
    assert all(len(block) == block_size for block in blocks)
    return b"".join(blocks)
