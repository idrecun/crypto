def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        byte_array.append(byte)
    return bytes(byte_array)


def xor(data1: bytes, data2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data1, data2))


def lfsr(state: list[int], b: int) -> list[int]:
    stream = state + [0] * b
    for i in range(len(state), len(stream)):
        stream[i] = stream[i - 16] ^ stream[i - 15] ^ stream[i - 13] ^ stream[i - 4]
    return stream[len(state) :]


def encrypt(key: bytes, message: bytes) -> bytes:
    keystream = lfsr(bytes_to_bits(key), 8 * len(message))
    return xor(bits_to_bytes(keystream), message)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    keystream = lfsr(bytes_to_bits(key), 8 * len(ciphertext))
    return xor(bits_to_bytes(keystream), ciphertext)
