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
  b = R.to_bytes(192, "big") + m
  h = hashlib.sha256(b).digest()
  return int.from_bytes(h, "big") % q

def sign(m, a):
  r = 99999999
  R = pow(g, r, p)
  c = challenge(R, m)
  s = (r + a * c) % q
  return (R, s)

def verify(m, R, s, A):
  c = challenge(R, m)
  return pow(g, s, p) == (R * pow(A, c, p)) % p

a, A = generate_keys()
m1 = b"Zdravo, svete!"
R, s1 = sign(m1, a)
m2 = b"Vozdra, svete!"
R, s2 = sign(m2, a)


