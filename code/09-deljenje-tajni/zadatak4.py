import shamir
from shamir import g, p, q
from kurs import hash_obj

# Sigma protokol (Šaum-Pedersenov dokaz jednakosti diskretnih logaritama) kojim
# učesnik dokazuje da je njegov delimični dešifrat k_i = R^{s_i} ispravan, tj. da
# su A_i = g^{s_i} i k_i = R^{s_i} formirani istim eksponentom s_i. Protokol je
# Fiat-Šamir heuristikom pretvoren u neinteraktivan dokaz.


def prove(s_i, R):
    A_i = pow(g, s_i, p)
    k_i = pow(R, s_i, p)
    w = shamir.rand_scalar()
    T1, T2 = pow(g, w, p), pow(R, w, p)
    e = int.from_bytes(hash_obj((g, R, A_i, k_i, T1, T2)), "big") % q
    z = (w + e * s_i) % q
    return k_i, (T1, T2, z)


def verify(A_i, R, k_i, proof):
    T1, T2, z = proof
    e = int.from_bytes(hash_obj((g, R, A_i, k_i, T1, T2)), "big") % q
    return (pow(g, z, p) == (T1 * pow(A_i, e, p)) % p and
            pow(R, z, p) == (T2 * pow(k_i, e, p)) % p)


if __name__ == "__main__":
    s_i = 13579
    A_i = pow(g, s_i, p)
    R = pow(g, shamir.rand_scalar(), p)  # R iz nekog šifrata

    k_i, proof = prove(s_i, R)
    print(f"ispravan delimični dešifrat se prihvata: {verify(A_i, R, k_i, proof)}")

    # Zlonameran učesnik objavljuje pogrešno k_i' i ne može da priloži validan dokaz.
    fake = (k_i * g) % p
    print(f"pogrešan delimični dešifrat se prihvata: {verify(A_i, R, fake, proof)}")
