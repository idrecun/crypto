import shamir
from shamir import g, p


def encrypt(m, A):
    """ElGamal šifrovanje poruke m javnim ključem A = g^s."""
    r = shamir.rand_scalar()
    R = pow(g, r, p)
    k = pow(A, r, p)            # k = g^{rs}
    return R, (k * m) % p


def partial_decrypt(R, s_i):
    """Delimični dešifrat učesnika i: k_i = R^{s_i}."""
    return pow(R, s_i, p)


def combine(R, c, partials):
    """Dešifrovanje na osnovu delimičnih dešifrata bar t+1 učesnika.

    partials je rečnik {i: k_i}. Tajna s se pri tome ne rekonstruiše direktno,
    već se k = R^s dobija kao k = prod_i k_i^{l_i(0)}.
    """
    coeffs = shamir.lagrange(list(partials))
    k = 1
    for i, k_i in partials.items():
        k = (k * pow(k_i, coeffs[i], p)) % p
    return (c * pow(k, -1, p)) % p


if __name__ == "__main__":
    s = 987654321
    A = pow(g, s, p)
    parts = shamir.share(s, t=2, n=5)

    m = 42
    R, c = encrypt(m, A)

    # Tri učesnika sarađuju u dešifrovanju.
    grupa = [parts[0], parts[2], parts[4]]
    partials = {i: partial_decrypt(R, s_i) for i, s_i in grupa}
    print(f"dešifrovano ispravno: {combine(R, c, partials) == m}")
