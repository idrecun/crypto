from kurs import xor


def encrypt(key: bytes, iv: bytes, message: bytes) -> bytes:
    generator = G(key + iv)
    keystream = generator.generate(len(message))
    return xor(keystream, message)


def decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    generator = G(key + iv)
    keystream = generator.generate(len(ciphertext))
    return xor(keystream, ciphertext)
