from kurs import xor

# P-box permutuje bajtove
pbox_table = [3, 0, 1, 2, 7, 4, 5, 6]


def pbox_inverse(block: bytes) -> bytes:
    return bytes(block[pbox_table.index(i)] for i in range(8))


def pbox(block: bytes) -> bytes:
    return bytes(block[i] for i in pbox_table)


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 8
    assert len(key) == 24
    keys = [key[i : i + 8] for i in range(0, 24, 8)]
    block = xor(block, keys[0])
    block = pbox(block)
    block = xor(block, keys[1])
    block = pbox(block)
    block = xor(block, keys[2])
    return block


m1 = bytes.fromhex("6a 61 3c 33 6d 61 74 66")
c1 = bytes.fromhex("1f 4c 06 10 1c 14 5a 05")

c2 = bytes.fromhex("59 1b 1c 1e 1e 53 45 05")

t = xor(m1, pbox_inverse(pbox_inverse(c1)))
m2 = xor(t, pbox_inverse(pbox_inverse(c2)))
print(m2)
