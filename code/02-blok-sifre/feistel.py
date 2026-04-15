from kurs import xor, feistel_k, feistel_f

key_expansion = feistel_k
f = feistel_f

ROUNDS = 8
BLOCK_SIZE = 8
block_size = BLOCK_SIZE


def round_function(key: bytes, block: bytes) -> bytes:
    n = len(block) // 2
    left, right = block[:n], block[n:]
    return right + xor(left, f(key, right))


def round_inverse(key: bytes, block: bytes) -> bytes:
    n = len(block) // 2
    left, right = block[:n], block[n:]
    return xor(right, f(key, left)) + left


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK_SIZE
    keys = key_expansion(key, ROUNDS)
    for k in keys:
        block = round_function(k, block)
    return block


def decrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK_SIZE
    keys = key_expansion(key, ROUNDS)
    for k in reversed(keys):
        block = round_inverse(k, block)
    return block
