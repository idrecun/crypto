"""Napad: prepisivanje istorije (zašto je dokaz rada bitan).

Izmena bilo kog ranijeg bloka odmah pada na proveri (Merkle koren i heš lanac se
ne poklapaju). Da bi izmena „prošla”, napadač mora ponovo da iskopa taj blok i
SVE blokove posle njega — dok pošteni čvorovi za to vreme produžavaju svoj lanac.
Bezbednost počiva na tome da napadač nema većinu računske snage.

Pokretanje: python napad_prepis.py
"""
import copy
import time

import block as blk
import chain as ch
import merkle
import transaction as tx
from params import node_keys, REWARD

C = ch.Blockchain.fresh()
for _ in range(3):                                     # pošteni lanac: genesis + 3
    cb = tx.make_coinbase(C.height + 1, node_keys(1)["t_pub"], REWARD)
    b = blk.mine(blk.make_block(C.height + 1, C.tip, [cb]))
    C = ch.Blockchain(C.blocks + [b])
print(f"pošten lanac visine {C.height}")

# Napadač preusmerava nagradu iz bloka 1 sebi.
forged = copy.deepcopy(C.blocks)
forged[1]["txs"][0]["outputs"][0]["owner"] = node_keys(9)["t_pub"]
try:
    ch.Blockchain(forged)
except ValueError as e:
    print("izmena bloka 1 odmah pada na proveri:", e)

# Da bi izmena prošla: prekopati blok 1 i sve naredne (popraviti veze + PoW).
t0, work = time.time(), 0
forged[1]["merkle_root"] = merkle.root([tx.txid(t) for t in forged[1]["txs"]])
for i in range(1, len(forged)):
    if i > 1:
        forged[i]["prev"] = blk.block_hash(forged[i - 1])
    forged[i]["nonce"] = 0
    while not blk.valid_pow(forged[i]):
        forged[i]["nonce"] += 1
        work += 1
ch.Blockchain(forged)                                  # sada je validan...
print(f"napadač je prekopao {len(forged) - 1} blokova ({work} heševa, {time.time() - t0:.1f}s)")
print("-> prepisivanje zahteva ponavljanje SVEG rada od izmenjenog bloka naovamo")
