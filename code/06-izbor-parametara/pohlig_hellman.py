import sys


def factors(n):
    result = []
    d = 2
    while d <= n:
        e = 0
        while n % d == 0:
            n //= d
            e += 1
        if e > 0:
            result.append((d, e))
        d += 1
    return result


def dlp_naive(g, h, n, p):
    t = 1
    for x in range(n):
        if t == h:
            return x
        t = (t * g) % p
    return None


# Radimo u grupi Z_p^* reda n = p - 1.
def pohlig_hellman(g, h, p):
    x = 0
    n = p - 1
    for pi, ei in factors(n):
        ti = pi ** ei
        gi = pow(g, n // ti, p)
        hi = pow(h, n // ti, p)
        xi = dlp_naive(gi, hi, ti, p)
        x += xi * (n // ti) * pow(n // ti, -1, ti)
    return x % n


if __name__ == "__main__":
    # p = 1019, p - 1 = 2 * 509 nije gladak; uzmimo p = 1009, p - 1 = 2^4 * 3^2 * 7.
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 1009
    g = int(sys.argv[2]) if len(sys.argv) > 2 else 11
    x_true = int(sys.argv[3]) if len(sys.argv) > 3 else 123
    h = pow(g, x_true, p)
    x = pohlig_hellman(g, h, p)
    print(f"pohlig_hellman(g={g}, h={h}, p={p}) = {x} (ocekivano {x_true})")
    print(f"provera: g^x mod p = {pow(g, x, p)}, h = {h}")
