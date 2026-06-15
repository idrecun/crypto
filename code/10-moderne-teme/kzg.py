"""KZG obavezivanje na polinome nad igračkim uparivanjem iz kurs.pairing.

U simetričnom uparivanju su generatori P i Q iz lekcije ista tačka G. Javni
parametri su stepeni tajne tau: g1 = [G, tau G, ..., tau^n G] i g2 = (G, tau G).
Tajna tau se posle generisanja mora uništiti.

Obaveza na f(x) = a_0 + a_1 x + ... + a_d x^d je C_f = sum a_i (tau^i G) =
f(tau) G. Dokaz da je f(z) = y je obaveza na količnik q(x) = (f(x) - y)/(x - z),
odnosno C_q = q(tau) G. Provera: e(C_f - yG, G) = e(C_q, tau G - z G).
"""

from kurs import pairing

G = pairing.G
q = pairing.q


def setup(tau, n):
    """Javni parametri za polinome stepena najviše n. tau je tajna (toksični
    otpad) i mora biti uništena nakon generisanja."""
    g1 = [pairing.mul(pow(tau, i, q), G) for i in range(n + 1)]
    g2 = (G, pairing.mul(tau % q, G))
    return g1, g2


def commit(g1, coeffs):
    """Obaveza C_f = sum a_i (tau^i G)."""
    C = None
    for ai, Ti in zip(coeffs, g1):
        C = pairing.add(C, pairing.mul(ai % q, Ti))
    return C


def poly_eval(coeffs, z):
    """f(z) mod q (Hornerova šema)."""
    y = 0
    for c in reversed(coeffs):
        y = (y * z + c) % q
    return y


def _div_x_minus_z(coeffs, z):
    """Podeli polinom (rastući koeficijenti) sa (x - z); vrati (količnik,
    ostatak) sintetičkim deljenjem nad Z_q."""
    desc = coeffs[::-1]
    out = [desc[0] % q]
    for c in desc[1:]:
        out.append((c + z * out[-1]) % q)
    rem = out[-1]
    quotient = out[:-1][::-1]
    return quotient, rem


def prove(g1, coeffs, z):
    """Dokaz da je f(z) = y. Vraća (C_q, y)."""
    y = poly_eval(coeffs, z)
    shifted = list(coeffs)
    shifted[0] = (shifted[0] - y) % q
    quotient, rem = _div_x_minus_z(shifted, z)
    assert rem == 0  # z je nula polinoma f(x) - y
    return commit(g1, quotient), y


def verify(g2, C_f, z, y, proof):
    """e(C_f - yG, G) == e(C_q, tau G - z G)."""
    Q, tauQ = g2
    lhs = pairing.pairing(pairing.sub(C_f, pairing.mul(y % q, G)), Q)
    rhs = pairing.pairing(proof, pairing.sub(tauQ, pairing.mul(z % q, Q)))
    return lhs == rhs


if __name__ == "__main__":
    import secrets

    tau = secrets.randbelow(q)
    n = 5
    g1, g2 = setup(tau, n)

    f = [3, 1, 4, 1, 5, 9]  # f(x) = 3 + x + 4x^2 + x^3 + 5x^4 + 9x^5
    C_f = commit(g1, f)
    z = 7
    proof, y = prove(g1, f, z)
    print(f"f({z}) = {y}")
    print(f"dokaz validan: {verify(g2, C_f, z, y, proof)}")
    print(f"lažna vrednost se odbija: {verify(g2, C_f, z, (y + 1) % q, proof)}")
