import ec


def factors(n):
    result = []
    d = 2
    while d * d <= n:
        e = 0
        while n % d == 0:
            n //= d
            e += 1
        if e > 0:
            result.append((d, e))
        d += 1
    if n > 1:
        result.append((n, 1))
    return result


def dlp_naive(G, H, n, a, p):
    R = None
    for x in range(n):
        if R == H:
            return x
        R = ec.add(R, G, a, p)
    return None


def crt(rs, ms):
    M = 1
    for m in ms:
        M *= m
    x = 0
    for r, m in zip(rs, ms):
        Mi = M // m
        x += r * Mi * pow(Mi, -1, m)
    return x % M


# Reseva x*G = H u podgrupi reda n nad krivom y^2 = x^3 + ax + b mod p.
def pohlig_hellman(G, H, n, a, p):
    rs, ms = [], []
    for q, e in factors(n):
        ti = q ** e
        Gi = ec.mul(n // ti, G, a, p)
        Hi = ec.mul(n // ti, H, a, p)
        xi = dlp_naive(Gi, Hi, ti, a, p)
        rs.append(xi)
        ms.append(ti)
    return crt(rs, ms)
