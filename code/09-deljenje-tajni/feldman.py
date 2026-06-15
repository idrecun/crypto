import shamir
from shamir import g, p, q


def commit(coeffs):
    """Feldmanove obaveze koeficijenata polinoma: C_k = g^{a_k}."""
    return [pow(g, c, p) for c in coeffs]


def deal(s, t, n):
    """Kao Šamirovo deljenje tajne, uz dodatno objavljivanje obaveza
    koeficijenata polinoma."""
    coeffs = shamir.random_poly(s, t)
    parts = [(i, shamir.eval_poly(coeffs, i)) for i in range(1, n + 1)]
    return parts, commit(coeffs)


def verify(part, commitments):
    """Učesnik proverava da je njegov deo (i, s_i) konzistentan sa obavezama,
    odnosno da li važi g^{s_i} = prod_k C_k^{i^k}."""
    i, s_i = part
    rhs = 1
    for k, C in enumerate(commitments):
        rhs = (rhs * pow(C, i ** k, p)) % p
    return pow(g, s_i, p) == rhs
