"""Demonstracija mreže: pokreni n čvorova, pošalji jednu transparentnu i jednu
skrivenu transakciju, pa potvrdi da su se svi čvorovi složili na istom lancu.

    python demo.py            # podrazumevano 3 čvora na localhost-u
"""
import os
import subprocess
import sys
import time

from kurs.network import connect_retry
from params import CLIENT_BASE

PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))
N = 3


def popen(*args):
    return subprocess.Popen([PY, *map(str, args)], cwd=HERE)


def command(index, msg, timeout=15):
    conn = connect_retry(CLIENT_BASE + index, timeout=timeout)
    conn.send(msg)
    reply = conn.recv()
    conn.close()
    return reply


def query(index):
    return command(index, ("query",))


def wait_until(pred, timeout=30, every=0.3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(every)
    return False


def main():
    nodes = [popen("node.py", i, N) for i in range(1, N + 1)]
    try:
        assert wait_until(lambda: all(query(i)["height"] >= 2 for i in range(1, N + 1))), \
            "mreža nije počela da kopa"
        print(f"mreža živa: {N} čvora kopaju i šire blokove\n")

        print("→ transparentna transakcija: čvor 1 plaća čvoru 2  (30 novčića)")
        print("  odgovor čvora 1:", command(1, ("pay_t", 2, 30)))
        assert wait_until(lambda: query(2)["t_balance"] >= 30), "čvor 2 nije dobio transparentnih 30"
        print("  ✓ čvor 2 vidi uplatu\n")

        print("→ skrivena transakcija: čvor 1 plaća čvoru 2  (iznos 40, sakriven na lancu)")
        print("  odgovor čvora 1:", command(1, ("pay_z", 2, 40)))
        assert wait_until(lambda: query(2)["z_balance"] == 40), "čvor 2 nije dobio skrivenih 40"
        print("  ✓ čvor 2 vidi skriveni saldo 40 (iznos je na lancu samo obaveza)\n")

        # Zamrzni kopanje da bismo dobili čistu sliku konsenzusa.
        for i in range(1, N + 1):
            command(i, ("mine", False))
        time.sleep(2.0)

        statuses = [query(i) for i in range(1, N + 1)]
        print("konačno stanje:")
        for s in statuses:
            print(f"  čvor {s['index']}: visina={s['height']}  vrh={s['tip'][:12]}…  "
                  f"t={s['t_balance']}  z={s['z_balance']}")

        tips = {s["tip"] for s in statuses}
        assert len(tips) == 1, f"čvorovi se NE slažu na vrhu lanca: {tips}"
        assert query(2)["t_balance"] >= 30 and query(2)["z_balance"] == 40
        print(f"\n✓ svi čvorovi se slažu na lancu visine {statuses[0]['height']}; "
              f"obe transakcije su potvrđene")
    finally:
        for p in nodes:
            p.terminate()
        for p in nodes:
            p.wait()


if __name__ == "__main__":
    main()
