"""Knjiga (ledger) i provera blokova/transakcija.

Stanje se sastoji od skupa nepotrošenih izlaza (UTXO), skupa potrošenih
transparentnih izlaza i skupa upotrebljenih slika ključeva. Lanac se proverava
ponovnim izvođenjem svih blokova od geneze (lanci su mali — igračka).

Najduži ispravan lanac je važeći: čvor prihvata tuđi lanac samo ako je ispravan
i duži od njegovog.
"""
import random
from kurs import ec_n, rangeproof
import merkle
import block as blk
import transaction as tx
import ecdsa
import ringsig
import ringct
from params import REWARD, node_keys


class State:
    def __init__(self):
        self.outputs = {}        # (txid, idx) -> izlaz
        self.spent_t = set()     # potrošeni transparentni izlazi
        self.key_images = set()  # upotrebljene slike ključeva (skrivene transakcije)

    def clone(self):
        s = State()
        s.outputs = dict(self.outputs)
        s.spent_t = set(self.spent_t)
        s.key_images = set(self.key_images)
        return s

    def _add_outputs(self, txid, outputs):
        for idx, o in enumerate(outputs):
            self.outputs[(txid, idx)] = o

    def apply_tx(self, t, genesis=False):
        kind = t["kind"]
        tid = tx.txid(t)
        if kind == "genesis":
            if not genesis:
                raise ValueError("genesis dozvoljen samo u prvom bloku")
        elif kind == "cb":
            if sum(o["amount"] for o in t["outputs"]) != REWARD:
                raise ValueError("pogrešna nagrada")
        elif kind == "t":
            self._spend_transparent(t)
        elif kind == "z":
            self._spend_shielded(t)
        else:
            raise ValueError(f"nepoznata vrsta transakcije: {kind}")
        self._add_outputs(tid, t["outputs"])

    def _spend_transparent(self, t):
        # TODO (vežbe): provera transparentne transakcije.
        #  - svaki ulaz (txid, idx) postoji u self.outputs, transparentan je i
        #    nije već u self.spent_t (nema dvostruke potrošnje),
        #  - svaki potpis je validan nad tx.transparent_message(ulazi, izlazi)
        #    u odnosu na vlasnika tog ulaza (ecdsa.verify),
        #  - zbir ulaznih iznosa == zbir izlaznih,
        #  - na kraju dodati potrošene ulaze u self.spent_t.
        raise NotImplementedError("provera transparentne transakcije")

    def _spend_shielded(self, t):
        # TODO (vežbe): provera skrivene (RingCT) transakcije.
        #  - za svaki ulaz: članovi prstena postoje i skriveni su (uzmi (P_i, C_i));
        #    slika ključa nije ranije upotrebljena; odgovara potpisu; MLSAG prolazi
        #    (ringsig.verify(tx.shielded_message(izlazi), ring_keys, Cp, sig)),
        #  - homomorfni bilans: ringct.balances(pseudo-obaveze ulaza, obaveze izlaza),
        #  - dokaz opsega na svakom izlazu (rangeproof.verify(o["C"], o["range"])),
        #  - na kraju dodati upotrebljene slike ključeva u self.key_images.
        raise NotImplementedError("provera skrivene (RingCT) transakcije")


class Blockchain:
    def __init__(self, blocks):
        self.blocks = list(blocks)
        self.state = State()
        for i, b in enumerate(self.blocks):
            self._apply_block(b, i)

    @classmethod
    def fresh(cls):
        return cls([genesis_block()])

    @property
    def height(self):
        return self.blocks[-1]["height"]

    @property
    def tip(self):
        return blk.block_hash(self.blocks[-1])

    def _apply_block(self, b, index):
        if b["height"] != index:
            raise ValueError("pogrešna visina bloka")
        if index == 0:
            if b["prev"] is not None:
                raise ValueError("genesis ne sme imati prethodnika")
        else:
            if b["prev"] != blk.block_hash(self.blocks[index - 1]):
                raise ValueError("blok se ne nadovezuje na prethodni")
            if not blk.valid_pow(b):
                raise ValueError("neispravan dokaz rada")
            if not b["txs"] or b["txs"][0]["kind"] != "cb":
                raise ValueError("blok mora počinjati coinbase transakcijom")
            if any(t["kind"] in ("cb", "genesis") for t in b["txs"][1:]):
                raise ValueError("coinbase/genesis na pogrešnom mestu")
        if b["merkle_root"] != merkle.root([tx.txid(t) for t in b["txs"]]):
            raise ValueError("Merkle koren ne odgovara transakcijama")
        for t in b["txs"]:
            self.state.apply_tx(t, genesis=(index == 0))

    def accepts(self, t):
        """Da li bi transakcija bila prihvaćena nad trenutnim stanjem (bez izmene)?"""
        try:
            self.state.clone().apply_tx(t)
            return True
        except ValueError:
            return False


def genesis_block():
    """Deterministička geneza (ista na svim čvorovima): čvor 1 dobija početni
    transparentni i poverljivi (skriveni) novac. Sistemski iskovani izlazi nemaju
    dokaz opsega, pa je geneza deterministička.

    Napomena: poverljivi premine poziva ringct.make_output — dok se Part 2 ne
    implementira, privremeno zakomentariši petlju ispod da bi radio čisto
    transparentan lanac."""
    rng = random.Random(20260615)
    k1 = node_keys(1)
    outputs = [{"owner": k1["t_pub"], "amount": 100}]      # transparentni premine
    for v in (50, 30, 20):                                 # poverljivi premine (ukupno 100)
        out, _ = ringct.make_output(k1["z_pub"], v, r=rng.randrange(1, ec_n), with_range=False)
        outputs.append(out)
    return blk.make_block(0, None, [tx.make_genesis(outputs)], nonce=0)
