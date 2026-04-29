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
  s = 0
  while s == 0: # osiguravamo da s nije 0
    r = 0
    while math.gcd(r, q) != 1:
      r = secrets.randbelow(q-1) + 1
    R = pow(g, r, p)
    s = (pow(r, -1, q) * (m - a * R)) % q
  return (R, s)

def verify(m, R, s, A):
  return pow(g, m, p) == (pow(R, s, p) * pow(A, R, p)) % p

# g^m = R^s * A^R
# probamo R = A*t, s = -R
# (A*t)^-R * A^R = t^(-R), ovo treba = g^m
# t = g^e, m = -e * R = e * s

a, A = generate_keys()
print(A)
e = 7
R = (pow(g, e, p) * A) % p
s = (-R) % q
m = (e * s) % q
print(verify(m, R, s, A))
