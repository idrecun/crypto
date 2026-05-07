import math
import sys


def sieve(n):
    is_prime = [True] * (n + 1)
    is_prime[0] = is_prime[1] = False
    for i in range(2, n + 1):
        if is_prime[i]:
            for j in range(i * i, n + 1, i):
                is_prime[j] = False
    return [i for i in range(n + 1) if is_prime[i]]


def pollard_p1(n, a, b):
    for p in sieve(b):
        t = 1
        while t * p <= b:
            t = t * p
        a = pow(a, t, n)
        g = math.gcd(a - 1, n)
        if g == n:
            return None
        if g > 1:
            return g
    return None


if __name__ == "__main__":
    # Primer: p = 1009, q = 1013, p - 1 = 2^4 * 3^2 * 7 je 16-gladak.
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1009 * 1013
    a = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    b = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    g = pollard_p1(n, a, b)
    if g is None:
        print(f"pollard_p1({n}, {a}, {b}) = neuspeh")
    else:
        print(f"pollard_p1({n}, {a}, {b}) = {g} (n / g = {n // g})")
