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

def encrypt(m, e, n):
    return pow(m, e, n)

def decrypt(c, d, n):
    return pow(c, d, n)
