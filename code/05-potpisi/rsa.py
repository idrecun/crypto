from Crypto.Util import number
import secrets
import math
import hashlib

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

def sign(m, d, n):
    h = hashlib.sha256(m).digest()
    return pow(int.from_bytes(h, "big"), d, n)

def verify(m, s, e, n):
    h = hashlib.sha256(m).digest()
    return int.from_bytes(h, "big") == pow(s, e, n)
