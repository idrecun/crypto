from kurs import AES_SBOX, xor


def sbox(block: bytes) -> bytes:
    return bytes(AES_SBOX[b] for b in block)


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 16
    assert len(key) == 16
    block = xor(block, key)
    block = sbox(block)
    block = xor(block, key)
    block = sbox(block)
    block = xor(block, key)
    block = sbox(block)
    block = xor(block, key)
    return block


def crack_sn(c1: bytes, m1: bytes, c2: bytes, m2: bytes) -> bytes:
    key = bytearray()
    for i in range(16):
        for k in range(256):
            enc1 = AES_SBOX[AES_SBOX[AES_SBOX[m1[i] ^ k] ^ k] ^ k] ^ k
            enc2 = AES_SBOX[AES_SBOX[AES_SBOX[m2[i] ^ k] ^ k] ^ k] ^ k
            if enc1 == c1[i] and enc2 == c2[i]:
                key.append(k)
                break
    return bytes(key)


m1 = bytes.fromhex("43 6f 6d 70 75 74 65 72 20 73 63 69 65 6e 63 65 ")
c1 = bytes.fromhex("a1 38 56 72 9f 84 99 a5 54 c5 84 1f 1b b5 28 99")
m2 = bytes.fromhex("52 61 63 75 6e 61 72 73 6b 65 20 6e 61 75 6b 65")
c2 = bytes.fromhex("d7 26 85 bb 4b 80 cf 49 ed a0 55 cc 26 ee 31 99")

print(crack_sn(c1, m1, c2, m2))
