from kurs import bytes_to_bits, bits_to_bytes, xor


def lfsr(state: list[int], b: int) -> list[int]:
    stream = state + [0] * b
    for i in range(len(state), len(stream)):
        stream[i] = stream[i - 16] ^ stream[i - 15] ^ stream[i - 13] ^ stream[i - 4]
    return stream[len(state) :]


def lfsr_reverse(state: list[int], b: int) -> list[int]:
    stream = [0] * b + state
    for j in range(b - 1, -1, -1):
        stream[j] = stream[j + 16] ^ stream[j + 12] ^ stream[j + 3] ^ stream[j + 1]
    return stream[:b]


def encrypt(key: bytes, message: bytes) -> bytes:
    keystream = lfsr(bytes_to_bits(key), 8 * len(message))
    return xor(bits_to_bytes(keystream), message)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    keystream = lfsr(bytes_to_bits(key), 8 * len(ciphertext))
    return xor(bits_to_bytes(keystream), ciphertext)


def encrypt_iv(key: bytes, iv: bytes, message: bytes) -> bytes:
    keystream = lfsr(bytes_to_bits(key + iv), 8 * len(message))
    return xor(bits_to_bytes(keystream), message)


def decrypt_iv(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    keystream = lfsr(bytes_to_bits(key + iv), 8 * len(ciphertext))
    return xor(bits_to_bytes(keystream), ciphertext)
