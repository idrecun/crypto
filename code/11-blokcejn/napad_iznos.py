"""Napad: kovanje novca „negativnim” iznosom (zašto su nužni dokazi opsega).

Kod poverljivih iznosa bilans se proverava homomorfno: suma ulaznih obaveza mora
biti jednaka sumi izlaznih. Ali sve je po modulu reda grupe, pa „negativan” iznos
(ogroman element polja) može lažno da zatvori bilans. Napadač iz ulaza vrednog 10
pravi izlaz vredan 70000 i drugi „negativan” izlaz koji namešta zbir.

Bez dokaza opsega bilans deluje ispravno i novac je iskovan. Sa dokazom opsega
napadač ne može ni da napravi dokaz za vrednost van [0, 2^16), pa se transakcija
odbija.

Pokretanje: python napad_iznos.py
"""
import confidential as cf
import pedersen
from kurs import ec_n, rangeproof

v_in, b_in = cf.make_output(10)[1]                     # pošten ulaz: 10
mint = 70000                                           # napadač želi da iskuje
neg = (10 - mint) % ec_n                               # „negativan” iznos (prelivanje)

b1 = pedersen.randomness()
b2 = (b_in - b1) % ec_n
evil = {
    "inputs": [pedersen.commit(v_in, b_in)],
    "outputs": [{"C": pedersen.commit(mint, b1)}, {"C": pedersen.commit(neg, b2)}],
}

print("bilans se homomorfno zatvara (deluje ispravno):", cf.balances(evil))
print(f"-> bez dokaza opsega napadač je iz 10 iskovao izlaz vredan {mint}")

print("sa dokazom opsega:")
for label, v in (("70000", mint), ("negativan", neg)):
    try:
        rangeproof.prove(v, b1)
        print(f"   {label}: dokaz napravljen?!")
    except ValueError:
        print(f"   {label}: dokaz opsega je NEMOGUĆ -> transakcija se odbija")
