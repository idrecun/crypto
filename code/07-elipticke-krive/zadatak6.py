import hashlib
from kurs import ec_G, ec_n
import ec

A = (246691936285505052706352817197487175489,
     10886859581935478975083534919891668598)


def challenge(m):
    return int.from_bytes(hashlib.sha256(m).digest(), "big") % ec_n


def verify(m, R, s, A):
    c = challenge(m)
    return ec.mul(s, ec_G) == ec.add(R, ec.mul(c, A))


# napad: c ne zavisi od R, pa biramo proizvoljno s i resimo R
# sG = R + cA  =>  R = sG - cA
m = b"Vozdra, svete!"
c = challenge(m)
s = 1
R = ec.sub(ec.mul(s, ec_G), ec.mul(c, A))

print(f"m = {m!r}")
print(f"R = {R}")
print(f"s = {s}")
print(f"provera: {verify(m, R, s, A)}")
