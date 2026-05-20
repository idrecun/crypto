"""Shared MD/Sponge helper functions for course exercises."""

import hashlib

from .conversions import xor
from .block_ciphers import spn_sbox, spn_pbox

MD_BLOCK_SIZE = 8
MD_IV = b"matfhash"

sbox = spn_sbox
pbox = spn_pbox

def md_f(state: bytes, block: bytes) -> bytes:
    assert len(state) == len(block) == MD_BLOCK_SIZE
    state = xor(state, block)
    state = sbox(state)
    state = pbox(state)
    state = xor(state, block)
    state = sbox(state)
    state = pbox(state)
    state = xor(state, block)
    state = sbox(state)
    return state

SPONGE_BLOCK_SIZE = 8

def sponge_f(state: bytes) -> bytes:
    assert len(state) == SPONGE_BLOCK_SIZE
    state = sbox(state)
    state = pbox(state)
    state = sbox(state)
    state = pbox(state)
    state = sbox(state)
    state = pbox(state)
    state = sbox(state)
    state = pbox(state)
    state = sbox(state)
    return state


def encode_obj(obj) -> bytes:
    """Canonical, type-tagged, length-prefixed serialization of nested objects.

    Supports None, bool, int, bytes, str, list/tuple, and dict (keys sorted by
    their own encoding). Used as the input to Fiat–Šamir challenge derivation.
    """
    if obj is None:
        return b"n"
    if isinstance(obj, bool):
        return b"B\x01" if obj else b"B\x00"
    if isinstance(obj, int):
        sign = b"-" if obj < 0 else b"+"
        n = abs(obj)
        body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        return b"i" + sign + len(body).to_bytes(4, "big") + body
    if isinstance(obj, bytes):
        return b"b" + len(obj).to_bytes(4, "big") + obj
    if isinstance(obj, str):
        data = obj.encode("utf-8")
        return b"s" + len(data).to_bytes(4, "big") + data
    if isinstance(obj, (list, tuple)):
        body = b"".join(encode_obj(x) for x in obj)
        return b"l" + len(obj).to_bytes(4, "big") + body
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: encode_obj(kv[0]))
        body = b"".join(encode_obj(k) + encode_obj(v) for k, v in items)
        return b"d" + len(items).to_bytes(4, "big") + body
    raise TypeError(f"encode_obj: unsupported type {type(obj).__name__}")


def hash_obj(obj) -> bytes:
    """SHA-256 of the canonical encoding of obj."""
    return hashlib.sha256(encode_obj(obj)).digest()


def _expand(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def hash_to_bits(obj, n: int) -> list[int]:
    """Derive n challenge bits from obj via SHA-256."""
    raw = _expand(encode_obj(obj), (n + 7) // 8)
    bits = []
    for byte in raw:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits[:n]


def hash_to_ints(obj, n: int, modulus: int) -> list[int]:
    """Derive n challenge integers in [0, modulus) from obj via SHA-256.

    Each integer uses (bit_length(modulus) + 128) bits of entropy so that the
    modular bias is statistically negligible.
    """
    byte_len = (modulus.bit_length() + 7) // 8 + 16
    raw = _expand(encode_obj(obj), n * byte_len)
    return [
        int.from_bytes(raw[i * byte_len : (i + 1) * byte_len], "big") % modulus
        for i in range(n)
    ]
