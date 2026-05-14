import hashlib
import math
import secrets
from kurs import ec_G, ec_n
import ec
import ecdh


def generate_keys():
    return ecdh.generate_keys()


def phi(R):
    return R[0] % ec_n


def sign(m, a):
    h = int.from_bytes(hashlib.sha256(m).digest(), "big") % ec_n
    s = 0
    while s == 0:
        r = 0
        while math.gcd(r, ec_n) != 1:
            r = secrets.randbelow(ec_n - 1) + 1
        R = ec.mul(r, ec_G)
        s = (pow(r, -1, ec_n) * (h - a * phi(R))) % ec_n
    return R, s


def verify(m, R, s, A):
    h = int.from_bytes(hashlib.sha256(m).digest(), "big") % ec_n
    return ec.mul(h, ec_G) == ec.add(ec.mul(s, R), ec.mul(phi(R), A))
