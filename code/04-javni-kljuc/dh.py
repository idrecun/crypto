from kurs import dh_g, dh_p
import secrets

def generate_keys():
  a = secrets.randbelow(dh_p-2) + 1
  A = pow(dh_g, a, dh_p)
  return a, A

def shared_key(a, B):
  return pow(B, a, dh_p)
