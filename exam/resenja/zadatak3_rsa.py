import hashlib
from Crypto.Util import number


def generate_keys(bits=1024):
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    return (pow(e, -1, phi), n), (e, n)


def _h(m):
    return int.from_bytes(hashlib.sha256(m).digest(), "big")


def sign(m, priv):
    d, n = priv
    return pow(_h(m), d, n)


def verify(m, s, pub):
    e, n = pub
    return pow(s, e, n) == _h(m) % n
