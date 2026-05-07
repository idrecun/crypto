import hashlib
import secrets

from pohlig_hellman import dlp_naive

g = 5
p = 102930135201232568905447342456556663645567
A = 9662939937200861840582525885171675976500
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


a = dlp_naive(g, A, q, p)
R, s = sign(M, a)

print(f"R = {R}")
print(f"s = {s}")
