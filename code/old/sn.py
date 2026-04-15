import aes


def sbox(block: bytes) -> bytes:
    return bytes(aes.sbox[b] for b in block)


def xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(b1, b2))


def encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == 16
    assert len(key) == 16
    keys = [key] * 4
    for k in keys[0:-1]:
        block = xor(block, k)
        block = sbox(block)
    block = xor(block, keys[-1])
    return block


def crack_sn(ciphertext: bytes, plaintext: bytes) -> bytes:
    assert len(ciphertext) == 16
    assert len(plaintext) == 16
    key = bytearray()
    for i in range(16):
        for k in range(256):
            p = plaintext[i]
            c = aes.sbox[aes.sbox[aes.sbox[p ^ k] ^ k] ^ k] ^ k
            if c == ciphertext[i]:
                key.append(k)
                break
    return bytes(key)


def cracka(ciphertext: bytes, plaintext: bytes) -> bytes:
    assert len(ciphertext) == 16
    assert len(plaintext) == 16
    key = bytearray()
    for i in range(16):
        for k in range(256):
            p = plaintext[i]
            c = aes.sbox[aes.sbox[aes.sbox[p ^ k] ^ k] ^ k] ^ k
            if c == ciphertext[i]:
                key.append(k)
        print(key)
        key = bytearray()
    return bytes(key)
