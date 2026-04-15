from kurs import xor
from md import md_hash

key = b"kripto01"
opad = b"\x5c" * 8
ipad = b"\x36" * 8

def hmac_naive(key: bytes, message: bytes) -> bytes:
    return md_hash(key + message)

def hmac(key: bytes, message: bytes) -> bytes:
    return md_hash(xor(key, opad) + md_hash(xor(key, ipad) + message))

if __name__ == "__main__":
    poruka = b"Zdravo, HMAC!"
    print("HMAC naive:", hmac_naive(key, poruka).hex())
    print("HMAC:", hmac(key, poruka).hex())
