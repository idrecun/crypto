import secrets
import sys

from miller_rabin import miller_rabin


def generate_safe_prime(bits, k=20):
    while True:
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        if not miller_rabin(q, k):
            continue
        p = 2 * q + 1
        if miller_rabin(p, k):
            return p


if __name__ == "__main__":
    bits = int(sys.argv[1]) if len(sys.argv) > 1 else 256
    p = generate_safe_prime(bits)
    q = (p - 1) // 2
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"p prime: {miller_rabin(p, 40)}, q prime: {miller_rabin(q, 40)}")
