from kurs import xor

# P-box permutuje bajtove
pbox_table = [3, 0, 1, 2, 7, 4, 5, 6]


def pbox(block: bytes) -> bytes:
    return bytes(block[i] for i in pbox_table)


def pbox_inverse(block: bytes) -> bytes:
    return bytes(block[pbox_table.index(i)] for i in range(8))


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 8
    assert len(key) == 16
    keys = [key[i : i + 8] for i in range(0, 16, 8)]
    block = xor(block, keys[0])
    block = pbox(block)
    block = xor(block, keys[1])
    return block


m1 = bytes.fromhex("62 6c 6f 6b 73 69 66 72")
c1 = bytes.fromhex("6d 64 64 3b 7d 7f 63 61")

c2 = bytes.fromhex("72 76 7a 3b 6e 63 69 69")

t = xor(m1, pbox_inverse(c1))
m2 = xor(t, pbox_inverse(c2))
print(m2)
