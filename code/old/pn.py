pbox_table = [3, 0, 1, 2, 7, 4, 5, 6]


def pbox(block: bytes) -> bytes:
    return bytes(block[i] for i in pbox_table)


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 8
    assert len(key) == 24
    keys = [key[i : i + 8] for i in range(0, 24, 8)]
    for k in keys[0:-1]:
        block = xor(block, k)
        block = pbox(block)
    block = xor(block, keys[-1])
    return block
