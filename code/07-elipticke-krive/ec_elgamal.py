import ec
import ecdh


def generate_keys():
    return ecdh.generate_keys()


def encrypt(M, A):
    r, R = ecdh.generate_keys()
    K = ecdh.shared_key(r, A)
    return R, ec.add(M, K)


def decrypt(R, C, a):
    K = ecdh.shared_key(a, R)
    return ec.sub(C, K)
