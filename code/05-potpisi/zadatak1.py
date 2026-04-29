from Crypto.Util import number
import secrets
import math
import hashlib

def generate_keys():
    p = number.getPrime(20)
    q = number.getPrime(20)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 0
    while math.gcd(e, phi) != 1:
        e = secrets.randbelow(phi - 2) + 2
    d = pow(e, -1, phi)

    return d, (n, e)

def sign(m, d, n):
    return pow(m, d, n)

def verify(m, s, e, n):
    return m == pow(s, e, n)

d, (n, e) = generate_keys()
print(e, n)

m1 = 12345
s1 = sign(m1, d, n)
m2 = 10000
s2 = sign(m2, d, n)

print(m1, s1, m2, s2)

m = (m1 * m2) % n
s = (s1 * s2) % n

print(verify(m, s, e, n))
