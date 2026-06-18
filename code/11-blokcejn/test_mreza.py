"""End-to-end testovi za lekciju 11 (blokčejn). Pokrenuti venv interpreterom:

    python test_mreza.py

Pokriva: kriptografske primitive, knjigu (transparentne i skrivene transakcije,
dvostruka potrošnja), pravu mrežu od tri čvora (demo.py) i sve napade.
"""
import os
import subprocess
import sys

PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))


def run(*args, timeout=180):
    return subprocess.run([PY, *map(str, args)], cwd=HERE,
                          capture_output=True, text=True, timeout=timeout)


def test_primitive():
    import secrets
    import ec, ecdsa, stealth, ringsig, ringct, merkle, pedersen, confidential
    from kurs import ec_G, ec_n

    a, A = ecdsa.keygen()
    assert ecdsa.verify(b"m", ecdsa.sign(b"m", a), A)

    # stealth + poverljivi izlaz: napravi izlaz, skeniraj ga i otvori iznos
    b, B = stealth.keygen()
    out, _ = ringct.make_output(B, 42)
    v, blind, x = ringct.scan(out, b, B)
    assert v == 42 and ec.mul(x, ec_G) == out["P"]
    assert ringct.scan(out, *stealth.keygen()) is None        # stranac ne vidi

    # MLSAG: prsten sa stvarnim izlazom + lažnjaci, pseudo-obaveza na isti iznos
    ring = [(ec.mul(secrets.randbelow(ec_n - 1) + 1, ec_G),
             pedersen.commit(secrets.randbelow(100), pedersen.randomness())) for _ in range(4)]
    ring[2] = (out["P"], out["C"])
    Cp, bp = ringct.pseudo_commit(42)
    sig = ringsig.sign(b"m", ring, Cp, 2, x, (blind - bp) % ec_n)
    assert ringsig.verify(b"m", ring, Cp, sig)
    assert not ringsig.verify(b"m", ring, pedersen.commit(99, bp), sig)   # lažan iznos pada
    assert ringsig.key_image(x) == sig[0]

    assert merkle.root(["a", "b", "c"]) == merkle.root(["a", "b", "c", "c"])  # CVE

    t = confidential.make_transfer([confidential.make_output(40)[1]], [25, 15])
    assert confidential.verify_transfer(t)
    return "primitive (ECDSA, stealth, MLSAG/RingCT, Merkle, poverljivi iznosi): OK"


def test_knjiga():
    import block as blk, chain as ch, transaction as tx
    from wallet import Wallet
    from params import REWARD, node_keys

    def mine(C, txs):
        cb = tx.make_coinbase(C.height + 1, node_keys(1)["t_pub"], REWARD)
        return ch.Blockchain(C.blocks + [blk.mine(blk.make_block(C.height + 1, C.tip, [cb] + txs))])

    w1, w2 = Wallet(1), Wallet(2)
    C = ch.Blockchain.fresh()
    assert w1.transparent_balance(C) == 100 and w1.shielded_balance(C) == 100
    C = mine(C, [w1.pay_transparent(C, w2.t_pub, 30)])
    assert w2.transparent_balance(C) == 30
    C = mine(C, [w1.pay_shielded(C, w2.z_pub, 35)])   # skriveni iznos
    assert w2.shielded_balance(C) == 35 and w1.shielded_balance(C) == 65
    # dvostruka potrošnja istih skrivenih ulaza (zastareo lanac) se odbija
    stale = w1.pay_shielded(C, w2.z_pub, 40)
    C = mine(C, [w1.pay_shielded(C, w2.z_pub, 40)])
    assert not C.accepts(stale)
    return "knjiga (transparentno + RingCT skriveno + odbijena dvostruka potrošnja): OK"


def test_mreza():
    out = run("demo.py").stdout
    assert "svi čvorovi se slažu" in out, out
    return "mreža (3 čvora, konsenzus + obe transakcije potvrđene): OK"


def test_napadi():
    checks = {
        "napad_nonce.py": "rekonstruisan PRIVATNI KLJUČ tačan: True",
        "napad_kovkost.py": "DVA različita txid-a: True",
        "napad_falsifikat.py": "krađa sa pogrešnim potpisom prihvaćena: False",
        "napad_merkle.py": "isti koren za dve različite liste: True",
        "napad_dvostruka.py": "posle uključivanja prve, druga se odbija: True",
        "napad_iznos.py": "NEMOGUĆ",
        "napad_prepis.py": "prekopao",
    }
    for script, needle in checks.items():
        out = run(script).stdout
        assert needle in out, f"{script}: nije nađeno '{needle}'\n{out}"
    return f"napadi ({len(checks)} skripte): OK"


if __name__ == "__main__":
    for test in [test_primitive, test_knjiga, test_mreza, test_napadi]:
        print(test(), flush=True)
    print("\nsvi testovi prošli")
