from kurs import blocks_to_bytes, bytes_to_blocks, xor


def pad(cipher, message: bytes) -> bytes:
    padding = cipher.block_size - (len(message) % cipher.block_size)
    return message + bytes([padding] * padding)


def unpad(cipher, message: bytes) -> bytes:
    assert len(message) % cipher.block_size == 0
    padding = message[-1]
    assert 1 <= padding <= cipher.block_size
    assert message[-padding:] == bytes([padding] * padding)
    return message[:-padding]


def encrypt_ecb(cipher, key: bytes, message: bytes) -> bytes:
    blocks = bytes_to_blocks(message, cipher.block_size)
    ciphertext = bytes()
    for block in blocks:
        ciphertext += cipher.encrypt_block(key, block)
    return ciphertext


def decrypt_ecb(cipher, key: bytes, ciphertext: bytes) -> bytes:
    blocks = bytes_to_blocks(ciphertext, cipher.block_size)
    message = bytes()
    for block in blocks:
        message += cipher.decrypt_block(key, block)
    return message


def encrypt_cbc(cipher, key: bytes, message: bytes, iv: bytes) -> bytes:
    assert len(iv) == cipher.block_size
    blocks = bytes_to_blocks(message, cipher.block_size)
    cipher_blocks = [iv]
    for block in blocks:
        cipher_blocks.append(cipher.encrypt_block(key, xor(block, cipher_blocks[-1])))
    return blocks_to_bytes(cipher_blocks)


def decrypt_cbc(cipher, key: bytes, ciphertext: bytes) -> bytes:
    blocks = bytes_to_blocks(ciphertext, cipher.block_size)
    message = bytes()
    for i in range(1, len(blocks)):
        message += xor(cipher.decrypt_block(key, blocks[i]), blocks[i - 1])
    return message


def encrypt_ctr(cipher, key: bytes, message: bytes, n: int) -> bytes:
    keystream = bytes()
    for i in range(0, 1 + len(message) // cipher.block_size):
        keystream += cipher.encrypt_block(key, int.to_bytes(n + i, cipher.block_size))
    return xor(message, keystream[: len(message)])


def decrypt_ctr(cipher, key: bytes, ciphertext: bytes, n: int) -> bytes:
    keystream = bytes()
    for i in range(0, 1 + len(ciphertext) // cipher.block_size):
        keystream += cipher.encrypt_block(key, int.to_bytes(n + i, cipher.block_size))
    return xor(ciphertext, keystream[: len(ciphertext)])
