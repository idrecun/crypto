"""Napad: dvostruka potrošnja skrivenog izlaza i uloga slike ključa.

Čvor 1 pravi dve skrivene transakcije koje troše ISTI ulaz, sa različitim
prstenovima lažnjaka. Svaka je pojedinačno validan MLSAG potpis. Ali pošto je
slika ključa I = x·Hp(P) deterministička funkcija ključa, obe imaju istu sliku
ključa, pa čvorovi odbijaju drugu — a da pritom i dalje ne znaju koji je tačno
izlaz potrošen. (Bez praćenja slika ključeva dvostruka potrošnja bi prošla.)

Pokretanje: python napad_dvostruka.py
"""
import block as blk
import chain as ch
import transaction as tx
from params import node_keys, REWARD
from wallet import Wallet

C = ch.Blockchain.fresh()
w1, w2, w3 = Wallet(1), Wallet(2), Wallet(3)

z1 = w1.pay_shielded(C, w2.z_pub, 10)        # troši prvi ulaz...
z2 = w1.pay_shielded(C, w3.z_pub, 10)        # ...i opet isti prvi ulaz

print("obe transakcije pojedinačno validne:", C.accepts(z1), C.accepts(z2))
print("ali im je slika ključa ista:",
      z1["inputs"][0]["key_image"] == z2["inputs"][0]["key_image"])

# Uključi prvu u blok; druga sada pada zbog ponovljene slike ključa.
cb = tx.make_coinbase(C.height + 1, node_keys(1)["t_pub"], REWARD)
b = blk.mine(blk.make_block(C.height + 1, C.tip, [cb, z1]))
C2 = ch.Blockchain(C.blocks + [b])
print("posle uključivanja prve, druga se odbija:", not C2.accepts(z2))
print("-> slika ključa sprečava dvostruku potrošnju bez otkrivanja potrošenog izlaza")
