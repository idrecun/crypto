"""Igračko simetrično uparivanje na supersingularnoj eliptičkoj krivoj.

Namenjeno isključivo za zadatke iz lekcije o modernim temama (BLS potpisi, KZG
obaveze). NIJE kriptografski bezbedno: parametri su mali (grupa reda ~2^101) i
diskretni logaritam je rešiv. Cilj je da konkretni primeri budu čitljivi i da
jednakosti za proveru zaista važe.

Radimo sa krivom \\(E: y^2 = x^3 + a x\\) nad poljem \\(F_p\\) gde je \\(p
\\equiv 3 \\pmod 4\\). Takva kriva je supersingularna, ima \\(p + 1\\) tačaka i
stepen ugnežđivanja 2, pa uparivanje slika u \\(F_{p^2} = F_p[i]\\) (\\(i^2 =
-1\\)). Sve javne vrednosti (ključevi, potpisi, obaveze) su tačke iz
\\(E(F_p)\\) — parovi celih brojeva po modulu \\(p\\). Aritmetika nad
\\(F_{p^2}\\) i Milerova petlja su interni detalji funkcije ``pairing``.

Koristi se simetrično uparivanje \\(e(P, Q)\\) sa distorzionim preslikavanjem
\\(\\phi(x, y) = (-x, i y)\\), tako da su obe grupe \\(G_1, G_2\\) iz lekcije
ovde ista grupa \\(G = \\langle G \\rangle\\) reda \\(q\\).
"""

import hashlib

# Parametri (videti gen_zadaci.py): p = 4q - 1, p i q prosti, p = 3 (mod 4).
p = 5070602400912917605986812874043
q = 1267650600228229401496703218511
a = 1
G = (3123222405771183912285272371589, 889621347109211773105306626444)

cofactor = (p + 1) // q  # = 4


# --- Aritmetika u F_{p^2} = F_p[i], elementi su parovi (re, im) ---

def _f2(x):
    return (x % p, 0)


def _f2sub(A, B):
    return ((A[0] - B[0]) % p, (A[1] - B[1]) % p)


def _f2mul(A, B):
    a0, a1 = A
    b0, b1 = B
    return ((a0 * b0 - a1 * b1) % p, (a0 * b1 + a1 * b0) % p)


def _f2scalar(k, A):
    return ((k * A[0]) % p, (k * A[1]) % p)


def _f2inv(A):
    a0, a1 = A
    n = pow((a0 * a0 + a1 * a1) % p, -1, p)
    return ((a0 * n) % p, (-a1 * n) % p)


def _f2div(A, B):
    return _f2mul(A, _f2inv(B))


def _f2pow(A, e):
    R = (1, 0)
    while e > 0:
        if e & 1:
            R = _f2mul(R, A)
        A = _f2mul(A, A)
        e >>= 1
    return R


# --- Grupa tačaka E(F_p): tačke su parovi (x, y), None je tačka u beskonačnosti ---

def on_curve(P):
    if P is None:
        return True
    x, y = P
    return (y * y - x * x * x - a * x) % p == 0


def neg(P):
    if P is None:
        return None
    return (P[0], (-P[1]) % p)


def add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        s = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        s = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)


def sub(P, Q):
    return add(P, neg(Q))


def mul(k, P):
    if P is None or k == 0:
        return None
    if k < 0:
        return mul(-k, neg(P))
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        k >>= 1
    return R


# --- Uparivanje: simetrična (redukovana) Tate-ova varijanta ---

def _distortion(Q):
    """phi(x, y) = (-x, i y); slika tačke iz E(F_p) u E(F_{p^2})."""
    x, y = Q
    return ((-x % p, 0), (0, y % p))


def _line(A, B, S):
    """Vrednost (prava kroz A, B)/(vertikala kroz A+B) u tački S nad F_{p^2}.
    A i B su tačke iz E(F_p)."""
    xS, yS = S
    xA, yA = A
    if A == B:
        lam = ((3 * xA * xA + a) * pow(2 * yA, -1, p)) % p
        xC = (lam * lam - 2 * xA) % p
    else:
        xB, yB = B
        if (xA - xB) % p == 0:  # vertikalna prava, A + B = O
            return _f2sub(xS, _f2(xA))
        lam = ((yB - yA) * pow(xB - xA, -1, p)) % p
        xC = (lam * lam - xA - xB) % p
    num = _f2sub(yS, _f2(yA))
    num = _f2sub(num, _f2scalar(lam, _f2sub(xS, _f2(xA))))
    den = _f2sub(xS, _f2(xC))
    return _f2div(num, den)


def _miller(P, S):
    """f_{q, P}(S) Milerovim algoritmom; P iz E(F_p), S iz E(F_{p^2})."""
    f = (1, 0)
    T = P
    for i in range(q.bit_length() - 2, -1, -1):
        f = _f2mul(_f2mul(f, f), _line(T, T, S))
        T = add(T, T)
        if (q >> i) & 1:
            f = _f2mul(f, _line(T, P, S))
            T = add(T, P)
    return f


_FINAL_EXP = (p * p - 1) // q


def pairing(P, Q):
    """Simetrično uparivanje e(P, Q) -> element grupe G_T = mu_q < F_{p^2}^*.
    Vraća element F_{p^2} kao par (re, im). Bilinearno: e(aP, bQ) = e(P, Q)^{ab}.
    """
    if P is None or Q is None:
        return (1, 0)
    return _f2pow(_miller(P, _distortion(Q)), _FINAL_EXP)


def gt_mul(x, y):
    """Množenje u ciljnoj grupi G_T (F_{p^2})."""
    return _f2mul(x, y)


def gt_pow(x, e):
    """Stepenovanje u ciljnoj grupi G_T."""
    return _f2pow(x, e % q if e >= 0 else e)


# --- Heširanje poruke u tačku grupe G (za BLS) ---

def hash_to_point(message: bytes):
    """H: poruka -> tačka reda q na krivoj (pokušaj-i-uvećaj + množenje
    kofaktorom). Determinističko."""
    counter = 0
    while True:
        h = hashlib.sha256(message + counter.to_bytes(4, "big")).digest()
        x = int.from_bytes(h, "big") % p
        rhs = (x * x * x + a * x) % p
        if pow(rhs, (p - 1) // 2, p) == 1:
            y = pow(rhs, (p + 1) // 4, p)  # p = 3 (mod 4)
            P = mul(cofactor, (x, y))
            if P is not None:
                return P
        counter += 1


if __name__ == "__main__":
    import secrets

    eGG = pairing(G, G)
    print(f"e(G, G) = {eGG}")
    print(f"nedegenerisano (e(G,G) != 1): {eGG != (1, 0)}")
    print(f"e(G, G)^q == 1: {_f2pow(eGG, q) == (1, 0)}")

    s, t = secrets.randbelow(q), secrets.randbelow(q)
    lhs = pairing(mul(s, G), mul(t, G))
    rhs = _f2pow(eGG, (s * t) % q)
    print(f"bilinearnost e(sG, tG) == e(G,G)^(st): {lhs == rhs}")

    H = hash_to_point(b"Kvantni pozdrav!")
    print(f"H(m) na krivoj: {on_curve(H)}, reda q: {mul(q, H) is None}")
