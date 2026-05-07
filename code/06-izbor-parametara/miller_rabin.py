import random
import sys


def test(a, s, d, n):
    x = pow(a, d, n)
    if x == 1:
        return True
    for _ in range(s):
        t = x
        x = pow(x, 2, n)
        if x == 1:
            return t == n - 1
    return False


def miller_rabin(n, k):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        if not test(a, s, d, n):
            return False

    return True


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000000007
    k = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    print(f"miller_rabin({n}, {k}) = {miller_rabin(n, k)}")
