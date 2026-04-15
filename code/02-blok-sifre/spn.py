from kurs import xor, spn_sbox, spn_sinv, spn_pbox, spn_pinv, spn_k

sbox = spn_sbox
sbox_inverse = spn_sinv
pbox = spn_pbox
pbox_inverse = spn_pinv
key_expansion = spn_k

ROUNDS = 8
BLOCK_SIZE = 8
block_size = BLOCK_SIZE


def round_function(key: bytes, block: bytes) -> bytes:
    block = xor(block, key)
    block = sbox(block)
    block = pbox(block)
    return block


def round_inverse(key: bytes, block: bytes) -> bytes:
    block = pbox_inverse(block)
    block = sbox_inverse(block)
    block = xor(block, key)
    return block


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK_SIZE
    keys = key_expansion(key, ROUNDS)
    for k in keys[0:-1]:
        block = round_function(k, block)
    block = xor(block, keys[-1])
    return block


def decrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK_SIZE
    keys = key_expansion(key, ROUNDS)
    block = xor(block, keys[-1])
    for k in reversed(keys[0:-1]):
        block = round_inverse(k, block)
    return block
