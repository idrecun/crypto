"""Poverljivi izlazi (RingCT sloj) — sakrivaju iznose, stopljeno sa prstenom.

Svaki skriveni izlaz nosi Pedersenovu obavezu C = v·G + b·H, dokaz opsega (gotova
primitiva iz kurs.rangeproof) i iznos šifrovan za primaoca. Zaslepljujući faktor b
se izvodi determinististički iz stealth deljene tajne, pa primalac ne mora da ga
prima — dovoljno mu je da dešifruje v.

Bilans transakcije je homomorfan: zbir pseudo-obaveza ulaza minus zbir obaveza
izlaza mora biti neutralna tačka.
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
    with_range=False izostavlja dokaz opsega (sistemski novac u genezi)."""
    # TODO (vežbe): S = deljena tačka (stealth.sender_share); b = _mask(S);
    # izlaz = {"R", "P" = stealth.one_time_pub(S,B), "C" = pedersen.commit(v,b),
    #          "enc" = v ^ _pad(S)} i, ako with_range, "range" = rangeproof.prove(v,b).
    raise NotImplementedError("make_output: napravi poverljivi izlaz")


def scan(out, b_priv, B):
    """Ako je izlaz moj, vrati (v, b, x); inače None."""
    # TODO (vežbe): S = stealth.recipient_share(out["R"], b_priv); ako
    # stealth.one_time_pub(S, B) != out["P"] -> None; inače v = out["enc"] ^ _pad(S),
    # b = _mask(S); proveri pedersen.commit(v,b) == out["C"]; vrati
    # (v, b, stealth.one_time_priv(S, b_priv)).
    raise NotImplementedError("scan: prepoznaj i otvori sopstveni izlaz")


def pseudo_commit(v):
    """Pseudo-obaveza na iznos v sa svežim faktorom. Vraća (C', b')."""
    b_prime = pedersen.randomness()
    return pedersen.commit(v, b_prime), b_prime


def balances(input_pseudos, output_commits):
    """Homomorfna ravnoteža: suma(pseudo-obaveze ulaza) − suma(obaveze izlaza) == O."""
    # TODO (vežbe): saberi pseudo-obaveze ulaza, oduzmi obaveze izlaza (ec.add/ec.sub),
    # i proveri da je rezultat neutralna tačka (None).
    raise NotImplementedError("balances: homomorfna provera ravnoteže")
