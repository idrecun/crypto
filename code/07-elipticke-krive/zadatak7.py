import hashlib
from kurs import ec_G, ec_n
import ec

A = (1446342285746087496322261997989149864,
     51899882338286411277127986568238557735)

m1 = b"Hello, world!"
R1 = (91407655570239612505893793489075498927,
      25538088875613710856623369771771322160)
s1 = 311396362683851534909632246027045848057

m2 = b"Hello, matf!"
R2 = (91407655570239612505893793489075498927,
      25538088875613710856623369771771322160)
s2 = 32731572252507648075677496446020975539


def H(m):
    return int.from_bytes(hashlib.sha256(m).digest(), "big") % ec_n


# napad: oba potpisa koriste isto R, dakle isto r
# r*s1 = h1 - a*phi(R), r*s2 = h2 - a*phi(R) (mod n)
# r = (h1 - h2) / (s1 - s2)
# a = (h1 - r*s1) / phi(R)
phi_R = R1[0] % ec_n
r = ((H(m1) - H(m2)) * pow((s1 - s2) % ec_n, -1, ec_n)) % ec_n
a = ((H(m1) - r * s1) * pow(phi_R, -1, ec_n)) % ec_n

print(f"a = {a}")
print(f"provera: aG == A: {ec.mul(a, ec_G) == A}")
