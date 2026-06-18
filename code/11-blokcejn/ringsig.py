"""MLSAG — višeslojni povezivi prstenasti potpis (Monero RingCT).

Nadogradnja običnog povezivog prstenastog potpisa: svaki član prstena nosi
*više* ključeva (slojeva), a potpisnik na pravom (skrivenom) indeksu mora da zna
tajne za SVE svoje slojeve. Ovde koristimo dva sloja:

  - sloj potrošnje: javni ključ P_i (baza G), tajna x sa P_pi = x·G;
    uz to slika ključa I = x·Hp(P_pi) (baza Hp_i) sprečava dvostruku potrošnju;
  - sloj iznosa:    ključ K_i = C_i − C' (baza H), tajna z sa K_pi = z·H.

Sloj iznosa zatvara prsten samo ako je C_pi − C' obaveza na NULU u vrednosti,
tj. ako pseudo-obaveza C' krije isti iznos kao stvarno potrošeni izlaz — a da se
ne otkrije koji je to izlaz. Time se iznos vezuje za bilans (videti ringct.py),
bez otkrivanja vrednosti ni potrošenog izlaza.
"""
import secrets
from kurs import ec_G, ec_n, hash_obj, encode_obj
import ec
from pedersen import hash_to_point, H


def key_image(x, P=None):
    if P is None:
        P = ec.mul(x, ec_G)
    return ec.mul(x, hash_to_point(encode_obj(P)))


def _challenge(m, ring, Cp, I, commitments):
    return int.from_bytes(hash_obj((m, ring, Cp, I, commitments)), "big") % ec_n


def sign(m, ring, Cp, pi, x, z):
    """ring = [(P_i, C_i)]; Cp = pseudo-obaveza C'; pi = pravi indeks;
    x = jednokratni privatni ključ; z = b_in − b' (tako da je C_pi − Cp = z·H).
    Vraća potpis (I, c0, s, t) gde su s/t odgovori sloja potrošnje/iznosa."""
    n = len(ring)
    Hp = [hash_to_point(encode_obj(P)) for P, _ in ring]
    K = [ec.sub(C, Cp) for _, C in ring]
    I = ec.mul(x, Hp[pi])
    s, t, c = [0] * n, [0] * n, [0] * n

    alpha = secrets.randbelow(ec_n - 1) + 1
    beta = secrets.randbelow(ec_n - 1) + 1
    L0, L0i, L1 = ec.mul(alpha, ec_G), ec.mul(alpha, Hp[pi]), ec.mul(beta, H)
    c[(pi + 1) % n] = _challenge(m, ring, Cp, I, (L0, L0i, L1))

    for j in range(1, n):
        i = (pi + j) % n
        s[i], t[i] = secrets.randbelow(ec_n), secrets.randbelow(ec_n)
        L0 = ec.add(ec.mul(s[i], ec_G), ec.mul(c[i], ring[i][0]))
        L0i = ec.add(ec.mul(s[i], Hp[i]), ec.mul(c[i], I))
        L1 = ec.add(ec.mul(t[i], H), ec.mul(c[i], K[i]))
        c[(i + 1) % n] = _challenge(m, ring, Cp, I, (L0, L0i, L1))

    s[pi] = (alpha - c[pi] * x) % ec_n
    t[pi] = (beta - c[pi] * z) % ec_n
    return I, c[0], s, t


def verify(m, ring, Cp, sig):
    I, c0, s, t = sig
    n = len(ring)
    Hp = [hash_to_point(encode_obj(P)) for P, _ in ring]
    K = [ec.sub(C, Cp) for _, C in ring]
    c = c0
    for i in range(n):
        L0 = ec.add(ec.mul(s[i], ec_G), ec.mul(c, ring[i][0]))
        L0i = ec.add(ec.mul(s[i], Hp[i]), ec.mul(c, I))
        L1 = ec.add(ec.mul(t[i], H), ec.mul(c, K[i]))
        c = _challenge(m, ring, Cp, I, (L0, L0i, L1))
    return c == c0
