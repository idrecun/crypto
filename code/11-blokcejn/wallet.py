"""Novčanik čvora: čuva ključeve, skenira lanac za svojim izlazima i sastavlja
transakcije (transparentne i skrivene).
"""
import random
import secrets
from kurs import ec_n
import pedersen
import ringct
import ringsig
import transaction as tx
from params import node_keys


class Wallet:
    def __init__(self, index):
        self.index = index
        k = node_keys(index)
        self.t_priv, self.t_pub = k["t_priv"], k["t_pub"]
        self.z_priv, self.z_pub = k["z_priv"], k["z_pub"]

    # --- transparentni novac ------------------------------------------------
    def transparent_utxos(self, chain):
        s = chain.state
        return [(op, o) for op, o in s.outputs.items()
                if "owner" in o and o["owner"] == self.t_pub and op not in s.spent_t]

    def transparent_balance(self, chain):
        return sum(o["amount"] for _, o in self.transparent_utxos(chain))

    def pay_transparent(self, chain, recipient_pub, amount):
        chosen, total = [], 0
        for op, o in self.transparent_utxos(chain):
            chosen.append(op)
            total += o["amount"]
            if total >= amount:
                break
        if total < amount:
            raise ValueError("nedovoljno transparentnih sredstava")
        outputs = [{"owner": recipient_pub, "amount": amount}]
        if total > amount:                                   # kusur nazad meni
            outputs.append({"owner": self.t_pub, "amount": total - amount})
        return tx.make_transparent(chosen, outputs, [self.t_priv] * len(chosen))

    # --- skriveni (poverljivi) novac ----------------------------------------
    def shielded_inputs(self, chain):
        """Poverljivi izlazi koje posedujem i mogu da potrošim:
        lista (outpoint, v, b, x) — iznos, faktor zaslepljivanja, jednokratni ključ."""
        res = []
        for op, o in chain.state.outputs.items():
            if "P" not in o:
                continue
            scanned = ringct.scan(o, self.z_priv, self.z_pub)
            if scanned is None:
                continue
            v, b, x = scanned
            if ringsig.key_image(x) not in chain.state.key_images:
                res.append((op, v, b, x))
        return res

    def shielded_balance(self, chain):
        return sum(v for _, v, _, _ in self.shielded_inputs(chain))

    def pay_shielded(self, chain, recipient_pub, amount, ring_size=4):
        """Pošalji iznos `amount` adresi recipient_pub. Iznos je skriven
        (Pedersenova obaveza), kao i pošiljalac i primalac. Svaki ulaz se krije u
        prsten sa do (ring_size-1) lažnjaka iz lanca."""
        chosen, total = [], 0
        for rec in self.shielded_inputs(chain):
            chosen.append(rec)
            total += rec[1]
            if total >= amount:
                break
        if total < amount:
            raise ValueError("nedovoljno skrivenih sredstava")

        # izlazi: primaocu `amount`, kusur nazad meni
        out_specs = [(recipient_pub, amount)]
        if total > amount:
            out_specs.append((self.z_pub, total - amount))
        outputs, blindings = [], []
        for B, v in out_specs:
            o, (_, b_out) = ringct.make_output(B, v)
            outputs.append(o)
            blindings.append(b_out)

        # pseudo-faktori ulaza tako da im je zbir jednak zbiru faktora izlaza
        sum_b_out = sum(blindings) % ec_n
        b_primes = [pedersen.randomness() for _ in chosen[:-1]]
        b_primes.append((sum_b_out - sum(b_primes)) % ec_n)

        pool = [op for op, o in chain.state.outputs.items() if "P" in o]
        specs = []
        for (op, v, b, x), b_prime in zip(chosen, b_primes):
            decoys = random.sample([d for d in pool if d != op],
                                   min(ring_size - 1, len(pool) - 1))
            pi = secrets.randbelow(len(decoys) + 1)
            ring = decoys[:pi] + [op] + decoys[pi:]
            specs.append({
                "ring": ring,
                "ring_keys": [(chain.state.outputs[d]["P"], chain.state.outputs[d]["C"]) for d in ring],
                "Cp": pedersen.commit(v, b_prime),
                "pi": pi, "x": x, "z": (b - b_prime) % ec_n,
            })
        return tx.make_shielded(specs, outputs)
