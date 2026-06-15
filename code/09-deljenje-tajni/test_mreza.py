"""Mrežni end-to-end testovi za lekciju 9 — pokreće prave procese (servere,
učesnike i klijente) i proverava ishod. Pokrenuti venv interpreterom:

    python test_mreza.py

Biblioteke (shamir, feldman, pedersen_dkg, elgamal, schnorr) nemaju zaseban
demo — vežbaju se kroz same zadatke koje ovde testiramo.
"""
import os
import re
import subprocess
import sys

import shamir

PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))
N, T, SECRET = 5, 2, 1234567890


def run(*args, timeout=30):
    return subprocess.run([PY, *map(str, args)], cwd=HERE,
                          capture_output=True, text=True, timeout=timeout).stdout


def popen(*args):
    return subprocess.Popen([PY, *map(str, args)], cwd=HERE,
                            stdout=subprocess.PIPE, text=True)


def stop(procs):
    for p in procs:
        p.terminate()
    for p in procs:
        p.wait()


def test_zadatak1():
    server = popen("zadatak1_server.py")
    try:
        out = run("zadatak1_client.py")
        assert "grupe bez učesnika 2 se slažu: True" in out, out
        assert "grupe sa učesnikom 2 se razlikuju: True" in out, out
    finally:
        stop([server])
    return "zadatak 1 (Šamirov delilac, sabotaža učesnika 2): OK"


def test_zadatak4():
    parts = dict(shamir.share(SECRET, T, N))
    procs = [popen("zadatak4.py", i, N, T, parts[i]) for i in range(1, N + 1)]
    outs = [p.communicate(timeout=30)[0] for p in procs]
    new = {i: int(re.search(r"novi deo = (\d+)", out).group(1))
           for i, out in enumerate(outs, 1)}
    assert shamir.reconstruct([(i, new[i]) for i in (1, 2, 3)]) == SECRET, \
        "novi delovi ne rekonstruišu istu tajnu"
    mix = [(1, parts[1]), (2, new[2]), (3, new[3])]
    assert shamir.reconstruct(mix) != SECRET, "stari + novi delovi ne smeju da rade"
    return "zadatak 4 (P2P osvežavanje delova): nova tajna ista, stari beskorisni"


def test_zadatak6():
    procs = [popen("zadatak6_server.py", i, N, T) for i in range(1, N + 1)]
    try:
        out = run("zadatak6_client.py")
        assert "ispravno: True" in out, out
    finally:
        stop(procs)
    return "zadatak 6 (DKG + ElGamal prag-dešifrovanje): OK"


def test_zadatak8():
    procs = [popen("zadatak8_server.py", i, N, T) for i in range(1, N + 1)]
    try:
        out = run("zadatak8_client.py")
        assert "validan potpis: True" in out, out
    finally:
        stop(procs)
    return "zadatak 8 (DKG + Šnorov prag-potpis): OK"


if __name__ == "__main__":
    tests = [test_zadatak1, test_zadatak4, test_zadatak6, test_zadatak8]
    for test in tests:
        print(test(), flush=True)
    print("\nsvi mrežni testovi prošli")
