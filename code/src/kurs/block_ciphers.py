"""Shared Feistel/SPN helper functions for course exercises."""

from .constants import AES_SBOX
from .conversions import bits_to_bytes, bytes_to_bits, xor

SPN_PBOX_TABLE = (3, 0, 1, 2, 7, 4, 5, 6)
SPN_PINV_TABLE = (1, 2, 3, 0, 5, 6, 7, 4)

_AES_SINV = [0] * 256
for i, value in enumerate(AES_SBOX):
    _AES_SINV[value] = i


def _repeat_to_length(data: bytes, length: int) -> bytes:
    assert len(data) > 0
    return bytes(data[i % len(data)] for i in range(length))


def feistel_k(key: bytes, rounds: int) -> list[bytes]:
    assert rounds > 0
    assert len(key) > 0
    return [bytes(key[(i + j) % len(key)] for j in range(len(key))) for i in range(rounds)]


def feistel_f(key: bytes, right: bytes) -> bytes:
    if not right:
        return b""
    mixed = xor(right, _repeat_to_length(key, len(right)))
    return bytes(AES_SBOX[value] for value in mixed)


def spn_sbox(block: bytes) -> bytes:
    return bytes(AES_SBOX[value] for value in block)


def spn_sinv(block: bytes) -> bytes:
    return bytes(_AES_SINV[value] for value in block)


def spn_pbox(block: bytes) -> bytes:
    assert len(block) == 8
    bits = bytes_to_bits(block)
    shuffled = [0] * len(bits)
    for i in range(8):
        for j in range(8):
            shuffled[i * 8 + j] = bits[j * 8 + i]
    shuffled_bytes = bits_to_bytes(shuffled)
    return bytes(shuffled_bytes[i] for i in SPN_PBOX_TABLE)


def spn_pinv(block: bytes) -> bytes:
    assert len(block) == 8
    shuffled_bytes = bytes(block[i] for i in SPN_PINV_TABLE)
    shuffled = bytes_to_bits(shuffled_bytes)
    bits = [0] * len(shuffled)
    for i in range(8):
        for j in range(8):
            bits[j * 8 + i] = shuffled[i * 8 + j]
    return bits_to_bytes(bits)


def spn_k(key: bytes, rounds: int, block_size: int = 8) -> list[bytes]:
    assert rounds > 0
    assert block_size > 0
    assert len(key) >= block_size
    return [bytes(key[(i + j) % len(key)] for j in range(block_size)) for i in range(rounds)]
