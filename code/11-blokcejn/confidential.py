"""Poverljivi iznosi (confidential amounts) — sakrivaju koliko se prenosi.

Umesto da iznos stoji otvoreno, izlaz nosi Pedersenovu obavezu C = v·G + b·H.
Zbog homomorfizma, transakcija je u ravnoteži kada je

    suma(ulazne obaveze) − suma(izlazne obaveze) = O  (neutralna tačka),

što znači da je suma ulaznih iznosa jednaka sumi izlaznih — a da se sami iznosi
ne otkrivaju. Pošiljalac bira zaslepljujuće faktore izlaza tako da se zbir
poklopi sa zbirom ulaznih faktora.

Sama ravnoteža nije dovoljna: kako je sve po modulu reda grupe, „negativan” iznos
(velika vrednost koja se prelije) može lažno da zatvori bilans i tako iskuje
novac. Zato svaki izlaz nosi i dokaz opsega (range proof) koji potvrđuje da je
iznos u dozvoljenom opsegu. Dokaz opsega koristimo kao gotovu primitivu iz
`kurs.rangeproof` (videti napad `napadi/iznos.py` za prikaz problema bez njega).

Napomena: ovde je mehanizam prikazan odvojeno (bez prstena), radi jasnoće i
postupnog uvođenja. Stopljena verzija (pun RingCT) koju koristi sam čvor je u
ringct.py i ringsig.py (MLSAG).
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
    """Napravi poverljivu transakciju.
    input_secrets: lista (v, b) za ulaze koje trošimo (znamo vrednost i faktor);
    output_values: iznosi koje pravimo. Faktori izlaza se biraju tako da se
    zbir faktora poklopi sa ulaznim (da transakcija bude u ravnoteži)."""
    if sum(v for v, _ in input_secrets) != sum(output_values):
        raise ValueError("ulazni i izlazni iznosi se ne poklapaju")
    b_in = sum(b for _, b in input_secrets) % ec_n
    blindings = [pedersen.randomness() for _ in output_values[:-1]]
    blindings.append((b_in - sum(blindings)) % ec_n)      # poslednji zatvara bilans
    inputs = [pedersen.commit(v, b) for v, b in input_secrets]
    outputs = [make_output(v, b)[0] for v, b in zip(output_values, blindings)]
    return {"inputs": inputs, "outputs": outputs}


def balances(tx):
    """Homomorfna provera ravnoteže: suma(ulazi) − suma(izlazi) == O."""
    acc = None
    for C in tx["inputs"]:
        acc = ec.add(acc, C)
    for o in tx["outputs"]:
        acc = ec.sub(acc, o["C"])
    return acc is None


def verify_transfer(tx, check_range=True):
    if not balances(tx):
        return False
    if check_range:
        return all(rangeproof.verify(o["C"], o["range"]) for o in tx["outputs"])
    return True


if __name__ == "__main__":
    # Čvor ima dva poverljiva ulaza (40 i 10) i šalje 35, sebi vraća 15.
    ins = [make_output(40)[1], make_output(10)[1]]
    tx = make_transfer(ins, [35, 15])
    print("transakcija u ravnoteži:", balances(tx))
    print("svi dokazi opsega validni:", verify_transfer(tx))
    print("iznosi se ne vide iz transakcije — vidljive su samo obaveze:")
    for o in tx["outputs"]:
        print("   C =", o["C"])
