from kurs import ec_G, ec_n
import secrets
import ec


def generate_keys():
    a = secrets.randbelow(ec_n - 2) + 1
    A = ec.mul(a, ec_G)
    return a, A


def shared_key(a, B):
    return ec.mul(a, B)
