"""Stealth (jednokratne) adrese — sakrivaju primaoca transakcije.

Primalac ima par ključeva (b, B = bG). Pošiljalac za svaki izlaz bira slučajno r,
objavljuje R = rG i računa deljenu tačku S = rB (primalac dobija istu tačku kao
S = bR). Iz S se izvodi deljeni skalar ss = H(S), pa je jednokratni javni ključ
P = ss·G + B, a jednokratni privatni p = ss + b. Iz iste deljene tačke izvode se i
zaslepljujući faktor i maska iznosa za poverljive iznose (videti ringct.py).
"""
import secrets
from kurs import ec_G, ec_n, hash_obj
import ec


def keygen():
    b = secrets.randbelow(ec_n - 1) + 1
    return b, ec.mul(b, ec_G)


def sender_share(B, r=None):
    """Pošiljalac: vrati (R, S) gde je R = rG javni nonce, a S = rB deljena tačka.
    r se može zadati spolja (determinističko premine u genezi)."""
    if r is None:
        r = secrets.randbelow(ec_n - 1) + 1
    return ec.mul(r, ec_G), ec.mul(r, B)


def recipient_share(R, b):
    """Primalac: deljena tačka S = bR (= rB)."""
    return ec.mul(b, R)


def _ss(S):
    return int.from_bytes(hash_obj(S), "big") % ec_n


def one_time_pub(S, B):
    return ec.add(ec.mul(_ss(S), ec_G), B)


def one_time_priv(S, b):
    return (_ss(S) + b) % ec_n


def is_mine(R, P, b, B):
    return one_time_pub(recipient_share(R, b), B) == P
