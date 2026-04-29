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

def sign(m, a):
  h = int.from_bytes(hashlib.sha256(m).digest(), "big")
  s = 0
  while s == 0: # osiguravamo da s nije 0
    r = 0
    while math.gcd(r, q) != 1:
      r = secrets.randbelow(q-1) + 1
    R = pow(g, r, p)
    s = (pow(r, -1, q) * (h - a * R)) % q
  return (R, s)

def verify(m, R, s, A):
  h = int.from_bytes(hashlib.sha256(m).digest(), "big")
  return pow(g, h, p) == (pow(R, s, p) * pow(A, R, p)) % p
