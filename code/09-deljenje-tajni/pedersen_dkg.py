import secrets
import shamir
import feldman
from shamir import g, p, q
from kurs import hash_obj


def run_dkg(n, t):
    """Distribuirano generisanje ključa bez centralnog delioca.

    Svaki učesnik bira slučajan polinom stepena t i objavljuje obaveze njegovih
    koeficijenata. Učesnik i šalje deo f_i(j) učesniku j, koji ga proverava
    Feldmanovom proverom. Na kraju svaki učesnik sabira primljene delove i
    dobija svoj deo zajedničke tajne s = sum_i f_i(0).
    """
    polys = [shamir.random_poly(secrets.randbelow(q), t) for _ in range(n)]
    commitments = [feldman.commit(poly) for poly in polys]

    # s_{i,j} = f_i(j): deo koji učesnik i šalje učesniku j.
    shares = [[shamir.eval_poly(polys[i], j) for j in range(1, n + 1)]
              for i in range(n)]

    # Svaki učesnik proverava delove koje je primio od ostalih.
    for i in range(n):
        for j in range(1, n + 1):
            assert feldman.verify((j, shares[i][j - 1]), commitments[i])

    # Deo zajedničke tajne učesnika j: s_j = sum_i s_{i,j}.
    final = [(j, sum(shares[i][j - 1] for i in range(n)) % q)
             for j in range(1, n + 1)]

    # Zajednički javni ključ: A = g^s = prod_i C_{i,0}.
    A = 1
    for C in commitments:
        A = (A * C[0]) % p

    return final, A


def prove_knowledge(a):
    """Šnorov dokaz poznavanja vrednosti a za koju je C = g^a (Fiat-Šamir)."""
    C = pow(g, a, p)
    k = shamir.rand_scalar()
    K = pow(g, k, p)
    e = int.from_bytes(hash_obj((C, K)), "big") % q
    z = (k + e * a) % q
    return K, z


def verify_knowledge(C, proof):
    K, z = proof
    e = int.from_bytes(hash_obj((C, K)), "big") % q
    return pow(g, z, p) == (K * pow(C, e, p)) % p


if __name__ == "__main__":
    final, A = run_dkg(n=5, t=2)
    s = shamir.reconstruct(final[:3])
    print(f"javni ključ konzistentan: {pow(g, s, p) == A}")
    s2 = shamir.reconstruct([final[1], final[3], final[4]])
    print(f"druga grupa daje istu tajnu: {s == s2}")

    a = shamir.rand_scalar()
    proof = prove_knowledge(a)
    print(f"validan dokaz znanja: {verify_knowledge(pow(g, a, p), proof)}")
    print(f"dokaz za pogrešno C:  {verify_knowledge(pow(g, a + 1, p), proof)}")
