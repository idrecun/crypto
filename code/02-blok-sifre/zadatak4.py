from kurs import AES_SBOX, xor, bytes_to_bits, bits_to_bytes

pbox_table = [3, 0, 1, 2, 7, 4, 5, 6]
pbox_inverse_table = [1, 2, 3, 0, 5, 6, 7, 4]


def pbox(block: bytes) -> bytes:
    bits = bytes_to_bits(block)
    shuffled = [0] * len(bits)
    for i in range(8):
        for j in range(8):
            shuffled[i * 8 + j] = bits[j * 8 + i]
    shuffled_bytes = bits_to_bytes(shuffled)
    return bytes(shuffled_bytes[i] for i in pbox_table)


def pbox_inverse(block: bytes) -> bytes:
    shuffled_bytes = bytes(block[i] for i in pbox_inverse_table)
    shuffled = bytes_to_bits(shuffled_bytes)
    bits = [0] * len(shuffled)
    for i in range(8):
        for j in range(8):
            bits[j * 8 + i] = shuffled[i * 8 + j]
    return bits_to_bytes(bits)


def sbox(block: bytes) -> bytes:
    return bytes(AES_SBOX[b] for b in block)


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 8
    assert len(key) == 16
    k1, k2 = key[:8], key[8:]
    block = xor(block, k1)
    block = sbox(block)
    block = pbox(block)
    block = xor(block, k2)
    return block


def crack_spn(
    c1: bytes, m1: bytes, c2: bytes, m2: bytes, c3: bytes, m3: bytes
) -> bytes:
    pairs = []
    ic1 = pbox_inverse(c1)
    ic2 = pbox_inverse(c2)
    ic3 = pbox_inverse(c3)
    for i in range(8):
        for k1 in range(256):
            for k2 in range(256):
                enc1 = AES_SBOX[m1[i] ^ k1] ^ k2
                enc2 = AES_SBOX[m2[i] ^ k1] ^ k2
                enc3 = AES_SBOX[m3[i] ^ k1] ^ k2
                if ic1[i] == enc1 and ic2[i] == enc2 and ic3[i] == enc3:
                    pairs.append((k1, k2))
                    break
    key = bytearray(16)
    for i, (k1, k2) in enumerate(pairs):
        key[i] = k1
        key[i + 8] = k2
    key[8:] = pbox(key[8:])
    return bytes(key)


m1 = bytes.fromhex("726163756e617269")
c1 = bytes.fromhex("49c69a043f667533")
m2 = bytes.fromhex("73706d72657a613b")
c2 = bytes.fromhex("c11cdfed6a6a42a0")
m3 = bytes.fromhex("6173646667686b6c")
c3 = bytes.fromhex("fd809dee3393e9c5")
print(crack_spn(c1, m1, c2, m2, c3, m3))
