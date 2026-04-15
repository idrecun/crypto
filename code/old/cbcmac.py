from Crypto.Cipher import AES

block_size = 16


def bytes_to_blocks(message: bytes) -> list[bytes]:
    return [message[i : i + block_size] for i in range(0, len(message), block_size)]


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def mac(key: bytes, message: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    length = int.to_bytes(len(message), block_size)
    blocks = bytes_to_blocks(message) + [length]
    cipher = [int.to_bytes(0, block_size)]
    for block in blocks:
        cipher.append(aes.encrypt(xor(block, cipher[-1])))
    return cipher[-1]
