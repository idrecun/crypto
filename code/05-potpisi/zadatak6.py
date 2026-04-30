import secrets
import hashlib
import math

p = 804455613497485373990731588387
q = p - 1
g = 2

def generate_keys():
  a = 100000
  A = pow(g, a, p)
  return a, A

def challenge(R, m):
  h = hashlib.sha256(m).digest()
  return int.from_bytes(h, "big") % q

def sign(m, a):
  r = secrets.randbelow(q-1) + 1
  R = pow(g, r, p)
  c = challenge(R, m)
  s = (r + a * c) % q
  return (R, s)

def verify(m, R, s, A):
  c = challenge(R, m)
  return pow(g, s, p) == (R * pow(A, c, p)) % p

a, A = generate_keys()
print(A)

# napad: c ne zavisi od R, pa biramo proizvoljno m i s, i resimo R
m = b"Lazirana poruka"
c = challenge(0, m)
s = 1
R = (pow(g, s, p) * pow(A, -c, p)) % p
print(verify(m, R, s, A))
