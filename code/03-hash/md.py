from kurs import md_f, MD_IV, MD_BLOCK_SIZE, bytes_to_blocks

def pad(message: bytes, block_size: int) -> bytes:
    padded = message + b"\x80"
    pad_len = (-len(padded)) % block_size  # Koliko fali do punog bloka
    return padded + (b'\x00' * pad_len)

def md_hash(message: bytes) -> bytes:
    padded = pad(message, MD_BLOCK_SIZE)
    state = MD_IV
    for block in bytes_to_blocks(padded, MD_BLOCK_SIZE):
        state = md_f(state, block)
    return state

print(md_hash(b"Hello, world!").hex())
