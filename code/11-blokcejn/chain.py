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
        ins, outs, sigs = t["inputs"], t["outputs"], t["sigs"]
        if len(sigs) != len(ins):
            raise ValueError("broj potpisa != broj ulaza")
        msg = tx.transparent_message(ins, outs)
        seen, total_in = set(), 0
        for op, sig in zip(ins, sigs):
            if op in seen:
                raise ValueError("isti ulaz dvaput u transakciji")
            seen.add(op)
            o = self.outputs.get(op)
            if o is None or "owner" not in o:
                raise ValueError("ulaz ne postoji ili nije transparentan")
            if op in self.spent_t:
                raise ValueError("dvostruka potrošnja")
            if not ecdsa.verify(msg, sig, o["owner"]):
                raise ValueError("neispravan potpis")
            total_in += o["amount"]
        if total_in != sum(o["amount"] for o in outs):
            raise ValueError("zbir ulaza != zbir izlaza")
        self.spent_t |= seen

    def _spend_shielded(self, t):
        ins, outs = t["inputs"], t["outputs"]
        m = tx.shielded_message(outs)
        batch, pseudo_in = set(), []
        for inp in ins:
            ring, I, Cp, sig = inp["ring"], inp["key_image"], inp["Cp"], inp["sig"]
            if I in self.key_images or I in batch:
                raise ValueError("dvostruka potrošnja (ponovljena slika ključa)")
            batch.add(I)
            ring_keys = []
            for op in ring:
                o = self.outputs.get(op)
                if o is None or "P" not in o:
                    raise ValueError("član prstena ne postoji ili nije skriven")
                ring_keys.append((o["P"], o["C"]))
            if sig[0] != I:
                raise ValueError("slika ključa ne odgovara potpisu")
            if not ringsig.verify(m, ring_keys, Cp, sig):
                raise ValueError("neispravan MLSAG potpis")
            pseudo_in.append(Cp)
        # homomorfni bilans: suma pseudo-obaveza ulaza == suma obaveza izlaza
        if not ringct.balances(pseudo_in, [o["C"] for o in outs]):
            raise ValueError("bilans se ne zatvara")
        # dokazi opsega na izlazima — bez njih bi „negativan” iznos iskovao novac
        for o in outs:
            if not rangeproof.verify(o["C"], o["range"]):
                raise ValueError("neispravan dokaz opsega izlaza")
        self.key_images |= batch


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
    transparentni i poverljivi (skriveni) novac, pa može da plaća u oba režima.
    Sistemski iskovani izlazi nemaju dokaz opsega (iznos je po konstrukciji
    ispravan), pa je geneza deterministička."""
    rng = random.Random(20260615)
    k1 = node_keys(1)
    outputs = [{"owner": k1["t_pub"], "amount": 100}]      # transparentni premine
    for v in (50, 30, 20):                                 # poverljivi premine (ukupno 100)
        out, _ = ringct.make_output(k1["z_pub"], v, r=rng.randrange(1, ec_n), with_range=False)
        outputs.append(out)
    return blk.make_block(0, None, [tx.make_genesis(outputs)], nonce=0)
