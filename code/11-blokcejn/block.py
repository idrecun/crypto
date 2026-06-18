"""Blok i dokaz rada (proof of work).

Blok vezuje prethodni blok svojim hešom i obavezuje se na svoje transakcije
Merkle korenom. Dokaz rada traži nonce takav da heš zaglavlja ima dovoljno
vodećih nula (manji je od ciljne vrednosti).
"""
from kurs import hash_obj
import merkle
import transaction
from params import DIFFICULTY_BITS


def header_hash(height, prev, merkle_root, nonce):
    return hash_obj(("zaglavlje", height, prev, merkle_root, nonce))


def block_hash(blk):
    return header_hash(blk["height"], blk["prev"], blk["merkle_root"], blk["nonce"])


def make_block(height, prev, txs, nonce=0):
    root = merkle.root([transaction.txid(tx) for tx in txs])
    return {"height": height, "prev": prev, "txs": txs,
            "merkle_root": root, "nonce": nonce}


def target(bits=DIFFICULTY_BITS):
    return 1 << (256 - bits)


def valid_pow(blk, bits=DIFFICULTY_BITS):
    return int.from_bytes(block_hash(blk), "big") < target(bits)


def mine(blk, bits=DIFFICULTY_BITS):
    """Nađi nonce koji zadovoljava PoW (blokirajuća pretraga — za genezu/testove)."""
    while not valid_pow(blk, bits):
        blk["nonce"] += 1
    return blk
