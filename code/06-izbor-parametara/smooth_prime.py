import random
import sys

import miller_rabin
import pollard_p1


# Generise prost broj p reda velicine `bits` bitova takav da je p - 1
# B-gladak (svi prosti stepeni broja p - 1 su manji ili jednaki B).
def smooth_prime(bits, B, k=20):
    primes = pollard_p1.sieve(B)
    target = 1 << (bits - 1)
    while True:
        n = 2
        while n < target:
            p = random.choice(primes)
            t = p
            while t * p <= B:
                t *= p
            n *= t
        if miller_rabin.miller_rabin(n + 1, k):
            return n + 1


if __name__ == "__main__":
    bits = int(sys.argv[1]) if len(sys.argv) > 1 else 128
    B = int(sys.argv[2]) if len(sys.argv) > 2 else 1 << 16
    p = smooth_prime(bits, B)
    print(f"p = {p}")
    print(f"p - 1 = {p - 1}")
