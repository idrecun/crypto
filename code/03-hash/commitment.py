from md import md_hash
from secrets import token_bytes

def commit_naive(message: bytes) -> bytes:
    return md_hash(message)

def verify_naive(message: bytes, commitment: bytes) -> bool:
    return md_hash(message) == commitment

def commit(message: bytes) -> tuple[bytes, bytes]:
    r = token_bytes(16)
    c = md_hash(message + r)
    return c, r

def verify(message: bytes, commitment: bytes, r: bytes) -> bool:
    return md_hash(message + r) == commitment
