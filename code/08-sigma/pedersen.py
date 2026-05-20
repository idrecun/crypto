import hashlib
import secrets
from kurs import ec_G, ec_n, ec_p, ec_a, ec_b
import ec


# Drugi generator H sa nepoznatim diskretnim logaritmom u odnosu na G.
def _hash_to_point(seed: bytes):
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


G = ec_G
H = _hash_to_point(b"matf-kripto-pedersen-H")


def commit(x, r):
    return ec.add(ec.mul(x % ec_n, G), ec.mul(r % ec_n, H))


def verify(c, x, r):
    return c == commit(x, r)


def randomness():
    return secrets.randbelow(ec_n)


def rerandomize(c, r_prime):
    return ec.add(c, ec.mul(r_prime % ec_n, H))


if __name__ == "__main__":
    x, r = 42, randomness()
    c = commit(x, r)
    print(f"H = {H}")
    print(f"c = {c}")
    print(f"verify(c, x, r): {verify(c, x, r)}")
    print(f"verify(c, x+1, r): {verify(c, x + 1, r)}")

    # homomorfizam
    x1, r1 = 7, randomness()
    x2, r2 = 35, randomness()
    c1, c2 = commit(x1, r1), commit(x2, r2)
    c_sum = ec.add(c1, c2)
    print(f"c1+c2 obaveza na x1+x2={x1+x2}: {verify(c_sum, x1 + x2, r1 + r2)}")

    # rerandomizacija
    r_prime = randomness()
    c_rand = rerandomize(c, r_prime)
    print(f"rerandomizovana obaveza na isto x: {verify(c_rand, x, r + r_prime)}")
