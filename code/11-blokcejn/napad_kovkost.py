"""Napad: kovkost ECDSA potpisa (signature malleability).

Iz validnog potpisa (u, s) trivijalno se dobija drugi validan potpis (u, n − s)
iste poruke. Pošto txid zavisi i od potpisa, ista uplata dobija dva različita
txid-a — što je dovoljno da zbuni servise koji prate transakcije po txid-u
(istorijski problem koji je doprineo padu Mt. Gox-a). Šnorov potpis nema ovu
osobinu, što je jedan od razloga prelaska na njega.

Pokretanje: python napad_kovkost.py
"""
import ecdsa
import transaction as tx
from kurs import ec_n
from params import node_keys

a, A = node_keys(1)["t_priv"], node_keys(1)["t_pub"]
inputs = [("genesis-izlaz", 0)]
outputs = [{"owner": node_keys(2)["t_pub"], "amount": 10}]
t = tx.make_transparent(inputs, outputs, [a])
msg = tx.transparent_message(inputs, outputs)

print("originalni txid:", tx.txid(t).hex()[:16], " potpis validan:",
      ecdsa.verify(msg, t["sigs"][0], A))

u, s = t["sigs"][0]
t2 = {**t, "sigs": [(u, (-s) % ec_n)]}                 # (u, s) -> (u, n - s)
print("malleiran txid: ", tx.txid(t2).hex()[:16], " potpis validan:",
      ecdsa.verify(msg, t2["sigs"][0], A))
print("ista uplata, DVA različita txid-a:", tx.txid(t) != tx.txid(t2))
