"""MLSAG — višeslojni povezivi prstenasti potpis (Monero RingCT).

Nadogradnja običnog povezivog prstenastog potpisa: svaki član prstena nosi
*više* ključeva (slojeva), a potpisnik na pravom (skrivenom) indeksu mora da zna
tajne za SVE svoje slojeve. Koristimo dva sloja:

  - sloj potrošnje: javni ključ P_i (baza G), tajna x sa P_pi = x·G;
    uz to slika ključa I = x·Hp(P_pi) (baza Hp_i) sprečava dvostruku potrošnju;
  - sloj iznosa:    ključ K_i = C_i − C' (baza H), tajna z sa K_pi = z·H.

Sloj iznosa zatvara prsten samo ako pseudo-obaveza C' krije isti iznos kao
stvarno potrošeni izlaz (tj. C_pi − C' je obaveza na nulu), a da se ne otkrije
koji je to izlaz.
"""
import secrets
from kurs import ec_G, ec_n, hash_obj, encode_obj
import ec
from pedersen import hash_to_point, H


def key_image(x, P=None):
    # TODO (vežbe): I = x·Hp(P), gde je Hp(P) = hash_to_point(encode_obj(P)) i
    # P = x·G ako nije zadat.
    raise NotImplementedError("key_image: I = x·Hp(P)")


def _challenge(m, ring, Cp, I, commitments):
    return int.from_bytes(hash_obj((m, ring, Cp, I, commitments)), "big") % ec_n


def sign(m, ring, Cp, pi, x, z):
    """ring = [(P_i, C_i)]; Cp = pseudo-obaveza C'; pi = pravi indeks;
    x = jednokratni privatni ključ; z = b_in − b'. Vraća (I, c0, s, t)."""
    # TODO (vežbe): dvoslojni MLSAG (videti lekciju). Skica:
    #  - Hp[i] = hash_to_point(encode_obj(P_i)); K[i] = C_i − Cp; I = x·Hp[pi].
    #  - kreni od pravog člana sa slučajnim alpha, beta:
    #      L0 = alpha·G, L0i = alpha·Hp[pi], L1 = beta·H,
    #      c[(pi+1)%n] = _challenge(m, ring, Cp, I, (L0, L0i, L1)).
    #  - za lažne članove: slučajni s[i], t[i], pa
    #      L0 = s[i]·G + c[i]·P_i, L0i = s[i]·Hp[i] + c[i]·I,
    #      L1 = t[i]·H + c[i]·K[i], i nastavi lanac izazova.
    #  - zatvori: s[pi] = alpha − c[pi]·x,  t[pi] = beta − c[pi]·z.
    raise NotImplementedError("sign: dvoslojni MLSAG potpis")


def verify(m, ring, Cp, sig):
    # TODO (vežbe): rekonstruiši lanac izazova oko prstena za oba sloja i proveri
    # da se zatvara (c == c0). I, c0, s, t = sig; K[i] = C_i − Cp;
    # L0 = s[i]·G + c·P_i, L0i = s[i]·Hp[i] + c·I, L1 = t[i]·H + c·K[i].
    raise NotImplementedError("verify: proveri da se lanac izazova zatvara")
