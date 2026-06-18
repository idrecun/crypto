"""Stealth (jednokratne) adrese — sakrivaju primaoca transakcije.

Primalac ima par ključeva (b, B = bG). Pošiljalac za svaki izlaz bira slučajno r,
objavljuje R = rG i računa deljenu tačku S = rB (primalac dobija istu tačku kao
S = bR). Iz S se izvodi deljeni skalar ss = H(S), pa je jednokratni javni ključ
P = ss·G + B, a jednokratni privatni p = ss + b.
"""
import secrets
from kurs import ec_G, ec_n, hash_obj
import ec


def keygen():
    b = secrets.randbelow(ec_n - 1) + 1
    return b, ec.mul(b, ec_G)


def _ss(S):
    return int.from_bytes(hash_obj(S), "big") % ec_n


def sender_share(B, r=None):
    """Pošiljalac: (R, S) gde je R = rG javni nonce, a S = rB deljena tačka."""
    # TODO (vežbe): izaberi r (ako nije zadat), vrati (r·G, r·B).
    raise NotImplementedError("sender_share: javni nonce i deljena tačka")


def recipient_share(R, b):
    """Primalac: deljena tačka S = bR (= rB)."""
    # TODO (vežbe): vrati b·R.
    raise NotImplementedError("recipient_share: deljena tačka")


def one_time_pub(S, B):
    # TODO (vežbe): jednokratni javni ključ P = _ss(S)·G + B.
    raise NotImplementedError("one_time_pub: P = ss·G + B")


def one_time_priv(S, b):
    # TODO (vežbe): jednokratni privatni ključ p = _ss(S) + b (mod n).
    raise NotImplementedError("one_time_priv: p = ss + b")


def is_mine(R, P, b, B):
    # TODO (vežbe): izlaz je moj ako je one_time_pub(recipient_share(R, b), B) == P.
    raise NotImplementedError("is_mine: prepoznaj sopstveni izlaz")
