import hashlib
import math
import secrets

from pohlig_hellman import dlp_naive

g = 2
p = 4712211801531972521576351639088809533078043
A = 764106831585898804754070363523847426400175
q = p - 1

M = b"Hello, matf!"


def sign(m, a):
    h = int.from_bytes(hashlib.sha256(m).digest(), "big")
    s = 0
    while s == 0:
        r = 0
        while math.gcd(r, q) != 1:
            r = secrets.randbelow(q - 1) + 1
        R = pow(g, r, p)
        s = (pow(r, -1, q) * (h - a * R)) % q
    return (R, s)


a = dlp_naive(g, A, q, p)
R, s = sign(M, a)

print(f"R = {R}")
print(f"s = {s}")
