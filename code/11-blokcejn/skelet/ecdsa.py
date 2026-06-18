"""ECDSA na secp128r1 — onako kako je definisan u lekciji o eliptičkim krivama
(ElGamalov potpis sa sabiranjem, gde se umesto tačke R šalje samo phi(R) = R_x).
Potpis je par (u, s). Koristimo ga kao šemu potpisa za transparentne transakcije.
"""
import hashlib
import secrets
from kurs import ec_G, ec_n
import ec


def keygen():
    a = secrets.randbelow(ec_n - 1) + 1
    return a, ec.mul(a, ec_G)


def _hash(m: bytes) -> int:
    return int.from_bytes(hashlib.sha256(m).digest(), "big") % ec_n


def sign(m: bytes, a: int, k: int | None = None):
    """Potpisuje poruku m privatnim ključem a. Nonce k se može zadati spolja
    (koristimo to u demonstraciji napada na ponovljen nonce)."""
    while True:
        kk = k if k is not None else secrets.randbelow(ec_n - 1) + 1
        R = ec.mul(kk, ec_G)
        u = R[0] % ec_n
        if u == 0:
            continue
        s = (pow(kk, -1, ec_n) * (_hash(m) + a * u)) % ec_n
        if s == 0:
            continue
        return (u, s)


def verify(m: bytes, sig, A) -> bool:
    u, s = sig
    if not (1 <= u < ec_n and 1 <= s < ec_n):
        return False
    w = pow(s, -1, ec_n)
    R = ec.add(ec.mul((_hash(m) * w) % ec_n, ec_G), ec.mul((u * w) % ec_n, A))
    if R is None:
        return False
    return R[0] % ec_n == u
