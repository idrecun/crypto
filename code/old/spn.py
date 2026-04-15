import aes


def sbox(block: bytes) -> bytes:
    return bytes(aes.sbox[b] for b in block)


# P-box permutuje bajtove
pbox_table = [3, 0, 1, 2, 7, 4, 5, 6]
pbox_inverse_table = [1, 2, 3, 0, 5, 6, 7, 4]


def bytes_to_bits(block: bytes) -> list[int]:
    bits = []
    for byte in block:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        bytes_list.append(byte)
    return bytes(bytes_list)


def xor(block1: bytes, block2: bytes) -> bytes:
    return bytes(b1 ^ b2 for b1, b2 in zip(block1, block2))


# P tabela prvo rasporedjuje bitove tako da j-ti bit i-tog bajta
# postane i-ti bit j-tog bajta
# Zatim se vrsi permutacija bajtova
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


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 8
    assert len(key) == 16
    k1, k2 = key[:8], key[8:]
    block = xor(block, k1)
    block = sbox(block)
    block = pbox(block)
    block = xor(block, k2)
    return block


def crack_spn(pairs: list[tuple[bytes, bytes]]) -> bytes:
    candidates = [set() for _ in range(8)]
    for pair, (ciphertext, plaintext) in enumerate(pairs):
        assert len(ciphertext) == 8
        assert len(plaintext) == 8
        pair_candidates = [set() for _ in range(8)]
        unpermuted_ciphertext = pbox_inverse(ciphertext)
        for i in range(8):
            for k1 in range(256):
                for k2 in range(256):
                    p = plaintext[i]
                    c = aes.sbox[p ^ k1] ^ k2
                    c_expected = unpermuted_ciphertext[i]
                    if c == c_expected:
                        pair_candidates[i].add((k1, k2))
        if pair == 0:
            candidates = pair_candidates
        else:
            for i in range(8):
                candidates[i] &= pair_candidates[i]
    key = bytearray([0] * 16)
    for i in range(8):
        if len(candidates[i]) == 0:
            print(f"No candidates for key byte {i}")
            return bytes()
        k1, k2 = candidates[i].pop()
        key[i] = k1
        key[i + 8] = k2
        if len(candidates[i]) != 0:
            print(f"Additional candidates for key byte {i}: {candidates[i]}")
    key[8:] = pbox(bytes(key[8:]))
    return bytes(key)


k = b"matfcryptography"
m1 = b"racunari"
print(m1.hex())
m2 = b"spmreza;"
print(m2.hex())
m3 = b"asdfghkl"
print(m3.hex())
c1 = encrypt_block(k, m1)
print(c1.hex())
c2 = encrypt_block(k, m2)
print(c2.hex())
c3 = encrypt_block(k, m3)
print(c3.hex())
cracked = crack_spn([(c1, m1), (c2, m2), (c3, m3)])
print(cracked)
