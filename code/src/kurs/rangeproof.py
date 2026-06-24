"""Dokaz opsega (range proof) — gotova primitiva (crna kutija).

Pravi dokazi opsega koji se koriste u praksi (npr. Bulletproofs) izlaze iz okvira
ovog kursa i ovde NISU cilj učenja. Da bismo ipak mogli da pokrenemo poverljive
transakcije i odgovarajuće napade, dat je jednostavan ali korektan dokaz zasnovan
na razlaganju na bitove:

    prove(v, b)      -> dokaz da Pedersenova obaveza C = v·G + b·H krije
                        vrednost u opsegu 0 <= v < 2^BITS
    verify(C, dokaz) -> True/False, bez ikakvog saznanja o v

Generatori G i H su isti kao u Pedersenovom obavezivanju iz vežbi. Unutrašnjost
modula (aritmetika krive, ILI-dokazi po bitovima) namerno je sakrivena — koristi
se kao gotov alat.
"""
import hashlib
import secrets

from .hash import hash_obj
from .public_key import ec_a, ec_b, ec_p, ec_n, ec_G

BITS = 16  # dovoljno za igračke iznose; obaveza otkriva vrednost van [0, 2^BITS)


# --- interna aritmetika krive secp128r1 (skriveno) ---------------------------
def _add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P == _neg(Q):
        return None
    x1, y1 = P
    x2, y2 = Q
    if x1 != x2:
        s = ((y2 - y1) * pow(x2 - x1, -1, ec_p)) % ec_p
    else:
        s = ((3 * x1 * x1 + ec_a) * pow(2 * y1, -1, ec_p)) % ec_p
    x3 = (s * s - x1 - x2) % ec_p
    return (x3, (s * (x1 - x3) - y1) % ec_p)


def _neg(P):
    return None if P is None else (P[0], (-P[1]) % ec_p)


def _sub(P, Q):
    return _add(P, _neg(Q))


def _mul(k, P):
    if k % ec_n == 0 or P is None:
        return None
    k %= ec_n
    R = None
    while k:
        if k & 1:
            R = _add(R, P)
        P = _add(P, P)
        k >>= 1
    return R


def _hash_to_point(seed):
    counter = 0
    while True:
        x = int.from_bytes(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest(), "big") % ec_p
        rhs = (x * x * x + ec_a * x + ec_b) % ec_p
        if pow(rhs, (ec_p - 1) // 2, ec_p) == 1:
            return (x, pow(rhs, (ec_p + 1) // 4, ec_p))
        counter += 1


G = ec_G
H = _hash_to_point(b"matf-kripto-pedersen-H")  # isti H kao u pedersen.py


def _challenge(*parts):
    return int.from_bytes(hash_obj(parts), "big") % ec_n


# --- ILI-dokaz da obaveza C krije bit (0 ili 1) ------------------------------
def _prove_bit(C, bit, r):
    Y = [C, _sub(C, G)]                       # dlog baze H je r za granu `bit`
    e = [0, 0]
    z = [0, 0]
    T = [None, None]
    fake = 1 - bit
    e[fake] = secrets.randbelow(ec_n)
    z[fake] = secrets.randbelow(ec_n)
    T[fake] = _sub(_mul(z[fake], H), _mul(e[fake], Y[fake]))
    k = secrets.randbelow(ec_n)
    T[bit] = _mul(k, H)
    ee = _challenge(C, T[0], T[1])
    e[bit] = (ee - e[fake]) % ec_n
    z[bit] = (k + e[bit] * r) % ec_n
    return (e[0], e[1], z[0], z[1])


def _verify_bit(C, bit_proof):
    e0, e1, z0, z1 = bit_proof
    T0 = _sub(_mul(z0, H), _mul(e0, C))
    T1 = _sub(_mul(z1, H), _mul(e1, _sub(C, G)))
    return (e0 + e1) % ec_n == _challenge(C, T0, T1)


# --- javni interfejs ---------------------------------------------------------
def prove(v, b):
    if not (0 <= v < (1 << BITS)):
        raise ValueError("vrednost van opsega")
    bits = [(v >> i) & 1 for i in range(BITS)]
    rs = [secrets.randbelow(ec_n) for _ in range(BITS - 1)]
    s = sum(rs[i] * (1 << i) for i in range(BITS - 1)) % ec_n
    rs.append(((b - s) * pow(1 << (BITS - 1), -1, ec_n)) % ec_n)  # da zbir bude b
    commits = [_add(_mul(bits[i], G), _mul(rs[i], H)) for i in range(BITS)]
    proofs = [_prove_bit(commits[i], bits[i], rs[i]) for i in range(BITS)]
    return (commits, proofs)


def verify(C, proof):
    commits, proofs = proof
    if len(commits) != BITS or len(proofs) != BITS:
        return False
    acc = None
    for i in range(BITS):
        acc = _add(acc, _mul(1 << i, commits[i]))
    if acc != C:                              # bitovi se moraju sklopiti u C
        return False
    return all(_verify_bit(commits[i], proofs[i]) for i in range(BITS))
