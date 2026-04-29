import secrets
import hashlib
import math
from kurs import dh_g, dh_p

g = dh_g
p = dh_p
q = dh_p - 1

def generate_keys():
  a = secrets.randbelow(q-1) + 1
  A = pow(g, a, p)
  return a, A

def challenge(R, m):
  b = R.to_bytes(192, "big") + m
  h = hashlib.sha256(b).digest()
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
