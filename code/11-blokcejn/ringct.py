"""Poverljivi izlazi (RingCT sloj) — sakrivaju iznose, stopljeno sa prstenom.

Svaki skriveni izlaz nosi Pedersenovu obavezu C = v·G + b·H (umesto otvorenog
iznosa), dokaz opsega (gotova primitiva iz kurs.rangeproof) i iznos šifrovan za
primaoca. Zaslepljujući faktor b se izvodi determinististički iz stealth deljene
tajne, pa primalac ne mora da ga prima — dovoljno mu je da dešifruje v.

Bilans transakcije je homomorfan: zbir pseudo-obaveza ulaza minus zbir obaveza
izlaza mora biti neutralna tačka. Da pseudo-obaveza ne bi lažirala vrednost,
MLSAG (ringsig.py) dokazuje da krije isti iznos kao stvarno potrošeni izlaz.
"""
from kurs import ec_n, hash_obj, rangeproof
import ec
import pedersen
import stealth


def _mask(S):
    return int.from_bytes(hash_obj((S, b"maska")), "big") % ec_n


def _pad(S):
    return int.from_bytes(hash_obj((S, b"iznos")), "big")


def make_output(B, v, r=None, with_range=True):
    """Poverljivi izlaz za adresu B sa iznosom v. Vraća (izlaz, (v, b)).
    with_range=False izostavlja dokaz opsega (za sistemski iskovan novac u genezi,
    čiji je iznos po konstrukciji ispravan — i da bi geneza bila deterministička)."""
    R, S = stealth.sender_share(B, r)
    b = _mask(S)
    out = {
        "R": R,
        "P": stealth.one_time_pub(S, B),
        "C": pedersen.commit(v, b),
        "enc": v ^ _pad(S),
    }
    if with_range:
        out["range"] = rangeproof.prove(v, b)
    return out, (v, b)


def scan(out, b_priv, B):
    """Ako je izlaz moj, vrati (v, b, x) — iznos, faktor i jednokratni privatni
    ključ; inače None."""
    S = stealth.recipient_share(out["R"], b_priv)
    if stealth.one_time_pub(S, B) != out["P"]:
        return None
    v = out["enc"] ^ _pad(S)
    b = _mask(S)
    if pedersen.commit(v, b) != out["C"]:      # obaveza se ne otvara — preskoči
        return None
    return v, b, stealth.one_time_priv(S, b_priv)


def pseudo_commit(v):
    """Pseudo-obaveza na iznos v sa svežim faktorom. Vraća (C', b')."""
    b_prime = pedersen.randomness()
    return pedersen.commit(v, b_prime), b_prime


def balances(input_pseudos, output_commits):
    """Homomorfna ravnoteža: suma(pseudo-obaveze ulaza) − suma(obaveze izlaza) == O."""
    acc = None
    for Cp in input_pseudos:
        acc = ec.add(acc, Cp)
    for C in output_commits:
        acc = ec.sub(acc, C)
    return acc is None
