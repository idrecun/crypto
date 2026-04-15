from kurs import MD_IV, MD_BLOCK_SIZE, md_f, bytes_to_blocks

def pad(message: bytes) -> bytes:
    return message + b"\x00" * (-len(message) % MD_BLOCK_SIZE)

def h(message: bytes) -> bytes:
    state = MD_IV
    for block in bytes_to_blocks(pad(message), MD_BLOCK_SIZE):
        state = md_f(state, block)
    return state

if __name__ == "__main__":
    m1 = b"Zdravo"
    m2 = b"Zdravo\x00\x00"
    print(h(m1).hex())
    print(h(m2).hex())
