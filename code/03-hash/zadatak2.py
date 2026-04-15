from md import md_hash, MD_BLOCK_SIZE, bytes_to_blocks, pad, md_f

m = b"Zdravo, HMAC!"
t = bytes.fromhex("0875db087d836f15")

def mac(key: bytes, message: bytes) -> bytes:
  return md_hash(key + message)

def verify(key: bytes, message: bytes, tag: bytes) -> bool:
  return mac(key, message) == tag

def md_hash_iv(message: bytes, iv: bytes) -> bytes:
    padded = pad(message, MD_BLOCK_SIZE)
    state = iv
    for block in bytes_to_blocks(padded, MD_BLOCK_SIZE):
        state = md_f(state, block)
    return state

if __name__ == "__main__":
    ext = b"Zdravo"
    t2 = md_hash_iv(ext, t)
    m2 = pad(m, MD_BLOCK_SIZE) + ext
    print(f"Poruka: {m2}")
    print(f"Tag: {t2.hex()}")

    kljuc = b"kripto01"
    print(verify(kljuc, m, t))
    print(verify(kljuc, m2, t2))
