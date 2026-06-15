import hashlib
from kurs import ec_G, ec_n
import ec

A = (109467063707252142941786888194056392558,
     283624804562688076124413520142906544564)

m1 = b"Zdravo, svete!"
R1 = (69191772370633742414484574291592789683,
      150081736994045835000962439583877754103)
s1 = 275532418724142788316051765718430826437

m2 = b"Vozdra, svete!"
R2 = (69191772370633742414484574291592789683,
      150081736994045835000962439583877754103)
s2 = 22127400428374188013866090255927965142


def challenge(R, m):
    b = f"({R[0]},{R[1]})".encode() + m
    return int.from_bytes(hashlib.sha256(b).digest(), "big") % ec_n


# napad: oba potpisa koriste isto R, dakle isto r
# s1 = r + a*c1, s2 = r + a*c2 (mod n)
# a = (s1 - s2) / (c1 - c2)
c1 = challenge(R1, m1)
c2 = challenge(R2, m2)
a = ((s1 - s2) * pow((c1 - c2) % ec_n, -1, ec_n)) % ec_n

print(f"a = {a}")
print(f"provera: aG == A: {ec.mul(a, ec_G) == A}")
