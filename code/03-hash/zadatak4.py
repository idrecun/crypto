import hashlib

def h(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()

moguce_poruke = [b"DA", b"NE", b"SUZDRZAN"]
c = bytes.fromhex("d539cd97ca1a108f9f5e3f611d7606d84c0aa35ea1973304e479b99025124e16")

for poruka in moguce_poruke:
    if h(poruka) == c:
        print(f"Glas je: {poruka}")
