from kurs import dh_p
import dh

def generate_keys():
    return dh.generate_keys()

def encrypt(m, A):
    b, B = dh.generate_keys()
    k = dh.shared_key(b, A)
    return B, (k * m) % dh_p

def decrypt(B, c, a):
    k = dh.shared_key(a, B)
    return (c * pow(k, -1, dh_p)) % dh_p
