import hashlib
import secrets

from pohlig_hellman import dlp_naive

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


a = dlp_naive(g, A, q, p)
R, s = sign(M, a)

print(f"R = {R}")
print(f"s = {s}")
