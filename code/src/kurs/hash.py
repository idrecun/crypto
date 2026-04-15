"""Shared MD/Sponge helper functions for course exercises."""

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
