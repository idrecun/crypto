from Crypto.Util import number
import secrets
import math

def generate_keys():
    p = number.getPrime(1024)
    q = number.getPrime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 0
    while math.gcd(e, phi) != 1:
        e = secrets.randbelow(phi - 2) + 2
    d = pow(e, -1, phi)

    return d, (n, e)

def pad(m):
    # Jedan bajt lufta na početku
    padded_bytes = secrets.token_bytes(15) + m.to_bytes(240, "big")
    return int.from_bytes(padded_bytes, "big")

def unpad(m):
    padded_bytes = m.to_bytes(255, "big")
    return int.from_bytes(padded_bytes[15:], "big")

def encrypt(m, e, n):
    return pow(pad(m), e, n)

def decrypt(c, d, n):
    return unpad(pow(c, d, n))
