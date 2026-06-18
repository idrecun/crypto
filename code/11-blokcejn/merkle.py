"""Merkle stablo nad listom transakcija — daje jedan koren (otisak celog skupa)
i kratke dokaze pripadnosti za „lake” klijente (SPV).

Pravimo ga u Bitkoin stilu: ako je broj čvorova na nekom nivou neparan,
poslednji se duplira. (Upravo ta odluka otvara CVE-2012-2459 — videti napade.)
"""
from kurs import hash_obj


def leaf_hash(tx):
    return hash_obj(("list", tx))


def _node(a, b):
    return hash_obj(("cvor", a, b))


def root(txs):
    if not txs:
        return hash_obj(None)
    level = [leaf_hash(tx) for tx in txs]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])          # dupliraj poslednji
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def proof(txs, index):
    """Putanja dokaza za transakciju na poziciji index: lista (sused, je_li_desni)."""
    level = [leaf_hash(tx) for tx in txs]
    path, i = [], index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        path.append((level[i ^ 1], i & 1))
        level = [_node(level[j], level[j + 1]) for j in range(0, len(level), 2)]
        i //= 2
    return path


def verify(root_hash, tx, path):
    h = leaf_hash(tx)
    for sibling, is_right in path:
        h = _node(sibling, h) if is_right else _node(h, sibling)
    return h == root_hash
