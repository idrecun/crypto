import secrets

p = 804455613497485373990731588387
g = 2

def generate_keys():
  a = secrets.randbelow(p-2) + 1
  A = pow(g, a, p)
  return a, A

def encrypt(m, b, A):
  k = pow(A, b, p)
  return (k * m) % p
