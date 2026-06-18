"""Parametri igračkog blokčejna: težina, nagrada, portovi i (radi reproducibilnog
demoa) deterministički ključevi po čvoru.

Svaki čvor ima dva para ključeva:
  - transparentni (t): obična ECDSA adresa za Part 1 (vidljive transakcije),
  - skriveni (z): adresa (B = b·G) za stealth/prstenaste transakcije iz Part 2.
"""
import hashlib
from kurs import ec_G, ec_n
import ec

DIFFICULTY_BITS = 18     # broj vodećih nula u heš vrednosti bloka (igračka težina)
REWARD = 50              # nagrada za iskopan blok (transparentni novac)
MINE_BATCH = 20000       # koliko nonce-ova se proba pre nego što čvor osmotri mrežu

P2P_BASE = 13000         # port za vezu među čvorovima: P2P_BASE + index
CLIENT_BASE = 14000      # port za klijente (slanje transakcija/upit): CLIENT_BASE + index


def _scalar(label: str) -> int:
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % (ec_n - 1) + 1


def node_keys(i: int):
    """Vrati ključeve čvora i kao rečnik: t_priv/t_pub i z_priv/z_pub."""
    t = _scalar(f"matf-blokcejn-t-{i}")
    z = _scalar(f"matf-blokcejn-z-{i}")
    return {
        "t_priv": t, "t_pub": ec.mul(t, ec_G),
        "z_priv": z, "z_pub": ec.mul(z, ec_G),
    }
