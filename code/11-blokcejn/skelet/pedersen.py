import hashlib
import secrets
from kurs import ec_G, ec_n, ec_p, ec_a, ec_b
import ec


def hash_to_point(seed: bytes):
    """Determinističko preslikavanje niza bajtova u tačku krive (try-and-increment).
    Koristi se za drugi generator H, ali i za sliku ključa u prstenastom potpisu.
    """
    counter = 0
    while True:
        h = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        x = int.from_bytes(h, "big") % ec_p
        rhs = (x * x * x + ec_a * x + ec_b) % ec_p
        if pow(rhs, (ec_p - 1) // 2, ec_p) == 1:
            # ec_p ≡ 3 (mod 4), pa važi sqrt(r) = r^((p+1)/4) mod p
            y = pow(rhs, (ec_p + 1) // 4, ec_p)
            return (x, y)
        counter += 1


# Drugi generator H sa nepoznatim diskretnim logaritmom u odnosu na G.
G = ec_G
H = hash_to_point(b"matf-kripto-pedersen-H")


def commit(x, r):
    return ec.add(ec.mul(x % ec_n, G), ec.mul(r % ec_n, H))


def verify(c, x, r):
    return c == commit(x, r)


def randomness():
    return secrets.randbelow(ec_n)
