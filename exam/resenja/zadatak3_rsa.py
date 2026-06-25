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


def _h(m):
    return int.from_bytes(hashlib.sha256(m).digest(), "big")


def sign(m, d, n):
    return pow(_h(m), d, n)


def verify(m, s, e, n):
    return _h(m) == pow(s, e, n)
