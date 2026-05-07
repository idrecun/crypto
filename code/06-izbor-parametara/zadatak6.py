import hashlib
import secrets

from pohlig_hellman import pohlig_hellman, dlp_naive

g = 2
p = 4712211801531972521576351639088809533078043
A = 1603188968889680704645883369269027685268625
q = p - 1

M = b"Vozdra, svete!"


def challenge(R, m):
    b = R.to_bytes(192, "big") + m
    h = hashlib.sha256(b).digest()
    return int.from_bytes(h, "big") % q


def sign(m, a):
    r = secrets.randbelow(q - 1) + 1
    R = pow(g, r, p)
    c = challenge(R, m)
    s = (r + a * c) % q
    return (R, s)


def verify(m, R, s):
    c = challenge(R, m)
    return pow(g, s, p) == (R * pow(A, c, p)) % p


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
