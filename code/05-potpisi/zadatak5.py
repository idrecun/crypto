import secrets
import hashlib
import math

p = 804455613497485373990731588387
q = p - 1
g = 2

nonce = 1000

def generate_keys():
  a = 100000
  A = pow(g, a, p)
  return a, A

def challenge(R, m):
  b = R.to_bytes(192, "big") + m
  h = hashlib.sha256(b).digest()
  return int.from_bytes(h, "big") % q

def sign(m, a):
  global nonce
  r = nonce
  nonce += 1
  R = pow(g, r, p)
  c = challenge(R, m)
  s = (r + a * c) % q
  return (R, s)

def verify(m, R, s, A):
  c = challenge(R, m)
  return pow(g, s, p) == (R * pow(A, c, p)) % p

a, A = generate_keys()

m1 = b"Zdravo, svete!"
R1, s1 = sign(m1, a)

# napadac ne vidi sledece potpise
for _ in range(47):
  sign(b"interno", a)

m2 = b"Vozdra, svete!"
R2, s2 = sign(m2, a)
print(A)
print(R1, s1, R2, s2)

# napad: pretpostavljamo da se r povecava za d izmedju vidljivih potpisa
# s1 = r + a*c1, s2 = (r+d) + a*c2  =>  a*(c1 - c2) = s1 - s2 + d
c1 = challenge(R1, m1)
c2 = challenge(R2, m2)
for d in range(1, 1000):
  diff = (c1 - c2) % q
  if math.gcd(diff, q) != 1:
    continue
  a_cand = ((s1 - s2 + d) * pow(diff, -1, q)) % q
  if pow(g, a_cand, p) == A:
    print(d, a_cand == a)
    break
