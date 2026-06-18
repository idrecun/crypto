"""Poverljivi iznosi (confidential amounts) — sakrivaju koliko se prenosi.

Umesto da iznos stoji otvoreno, izlaz nosi Pedersenovu obavezu C = v·G + b·H.
Zbog homomorfizma, transakcija je u ravnoteži kada je

    suma(ulazne obaveze) − suma(izlazne obaveze) = O  (neutralna tačka),

što znači da je suma ulaznih iznosa jednaka sumi izlaznih — a da se sami iznosi
ne otkrivaju. Svaki izlaz dodatno nosi dokaz opsega (range proof, gotova primitiva
iz `kurs.rangeproof`) koji sprečava „negativne”/prelivene iznose.

Ovo je samostalan prikaz ideje (bez prstena); stopljena verzija (RingCT) koju
koristi sam čvor je u ringct.py / ringsig.py.
"""
from kurs import ec_n, rangeproof
import ec
import pedersen


def make_output(value, blinding=None):
    """Poverljivi izlaz: obaveza na `value` + dokaz opsega."""
    if blinding is None:
        blinding = pedersen.randomness()
    C = pedersen.commit(value, blinding)
    return {"C": C, "range": rangeproof.prove(value, blinding)}, (value, blinding)


def make_transfer(input_secrets, output_values):
    """input_secrets: lista (v, b) za ulaze; output_values: izlazni iznosi.
    Faktori izlaza se biraju tako da se zbir poklopi sa zbirom ulaznih faktora."""
    # TODO (vežbe): proveri da je suma ulaza == suma izlaza; izaberi zaslepljujuće
    # faktore izlaza tako da im je zbir jednak zbiru ulaznih (poslednji zatvara
    # bilans); vrati {"inputs": [obaveze ulaza], "outputs": [make_output(...) ]}.
    raise NotImplementedError("make_transfer: napravi poverljivu transakciju u ravnoteži")


def balances(tx):
    """Homomorfna provera ravnoteže: suma(ulazi) − suma(izlazi) == O."""
    # TODO (vežbe): saberi sve ulazne obaveze, oduzmi sve izlazne (ec.add/ec.sub) i
    # proveri da je rezultat neutralna tačka (None).
    raise NotImplementedError("balances: homomorfna provera ravnoteže")


def verify_transfer(tx, check_range=True):
    if not balances(tx):
        return False
    if check_range:
        return all(rangeproof.verify(o["C"], o["range"]) for o in tx["outputs"])
    return True
