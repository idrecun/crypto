import hashlib
import math
import secrets

from pohlig_hellman import pohlig_hellman, dlp_naive

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


def verify(m, R, s):
    h = int.from_bytes(hashlib.sha256(m).digest(), "big")
    return pow(g, h, p) == (pow(R, s, p) * pow(A, R, p)) % p


def brute_force():
    a = dlp_naive(g, A, q, p)
    return sign(M, a)


def solve():
    a = pohlig_hellman(g, A, p)
    return sign(M, a)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "brute":
        R, s = brute_force()
    else:
        R, s = solve()
    print(f"R = {R}")
    print(f"s = {s}")
    print(f"provera: {verify(M, R, s)}")
