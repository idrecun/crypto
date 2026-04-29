import secrets
import hashlib
import math

p = 804455613497485373990731588387
q = p - 1
g = 2

def generate_keys():
  a = 123
  A = pow(g, a, p)
  return a, A

def sign(m, a):
  h = int.from_bytes(hashlib.sha256(m).digest(), "big")
  s = 0
  while s == 0: # osiguravamo da s nije 0
    r = 137
    R = pow(g, r, p)
    s = (pow(r, -1, q) * (h - a * R)) % q
  return (R, s)

def verify(m, R, s, A):
  h = int.from_bytes(hashlib.sha256(m).digest(), "big")
  return pow(g, h, p) == (pow(R, s, p) * pow(A, R, p)) % p

a, A = generate_keys()
m1 = b'Hello, world!'
m2 = b'Hello, matf!'
R, s1 = sign(m1, a)
R, s2 = sign(m2, a)
print(R, s1, s2)
