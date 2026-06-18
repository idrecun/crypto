"""Napad: dvosmislenost Merkle korena zbog dupliranja poslednjeg lista
(CVE-2012-2459 iz Bitkoina).

Kako se neparan nivo popunjava dupliranjem poslednjeg čvora, liste [A,B,C] i
[A,B,C,C] imaju isti koren. Lak (SPV) klijent koji veruje samo korenu zato može
da bude ubeđen u skup transakcija koji se razlikuje od pravog. Odbrana: zabraniti
dupliranje (ili odvojiti domenom heš lista i unutrašnjih čvorova) i fiksirati broj
transakcija.

Pokretanje: python napad_merkle.py
"""
import merkle

real = ["A", "B", "C"]
fake = ["A", "B", "C", "C"]            # ubačena (duplirana) transakcija

print("koren([A,B,C])    =", merkle.root(real).hex()[:24])
print("koren([A,B,C,C])  =", merkle.root(fake).hex()[:24])
print("isti koren za dve različite liste:", merkle.root(real) == merkle.root(fake))

# SPV dokaz pripadnosti napravljen iz lažne liste prolazi proveru protiv pravog korena.
r = merkle.root(real)
path = merkle.proof(fake, 3)           # „dokaz” za ubačenu kopiju na poziciji 3
print("SPV klijent prihvata dokaz za ubačenu transakciju:", merkle.verify(r, "C", path))
print("-> klijent ne može da razlikuje pravu listu od napadnute")
