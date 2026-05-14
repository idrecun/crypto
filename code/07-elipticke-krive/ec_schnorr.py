import hashlib
import secrets
from kurs import ec_G, ec_n
import ec
import ecdh


def generate_keys():
    return ecdh.generate_keys()


def challenge(R, m):
    b = f"({R[0]},{R[1]})".encode() + m
    h = hashlib.sha256(b).digest()
    return int.from_bytes(h, "big") % ec_n


def sign(m, a):
    r = secrets.randbelow(ec_n - 1) + 1
    R = ec.mul(r, ec_G)
    c = challenge(R, m)
    s = (r + a * c) % ec_n
    return R, s


def verify(m, R, s, A):
    c = challenge(R, m)
    return ec.mul(s, ec_G) == ec.add(R, ec.mul(c, A))
