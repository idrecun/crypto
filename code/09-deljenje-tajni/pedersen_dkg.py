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


def run_dkg_peer(i, n, t, peers):
    """Distribuirano generisanje ključa iz ugla učesnika i, preko mreže.

    peers je rečnik {j: Connection} veza ka svim ostalim učesnicima (videti
    kurs.network.connect_mesh). Vraća (s_i, A): deo zajedničke tajne učesnika i
    i zajednički javni ključ A = g^s. Tajna s se nigde ne rekonstruiše."""
    poly = shamir.random_poly(secrets.randbelow(q), t)
    C_i = feldman.commit(poly)
    proof_i = prove_knowledge(poly[0])

    # Runda 1: razmena obaveza i Šnorovih dokaza poznavanja slobodnog člana.
    for conn in peers.values():
        conn.send((C_i, proof_i))
    commitments = {i: C_i}
    for j, conn in peers.items():
        C_j, proof_j = conn.recv()
        assert verify_knowledge(C_j[0], proof_j), f"loš dokaz učesnika {j}"
        commitments[j] = C_j

    # Runda 2: učesniku j se šalje njegov deo f_i(j), a primaju se delovi f_j(i).
    for j, conn in peers.items():
        conn.send(shamir.eval_poly(poly, j))
    s_i = shamir.eval_poly(poly, i)
    for j, conn in peers.items():
        s_ji = conn.recv()
        assert feldman.verify((i, s_ji), commitments[j]), f"loš deo od učesnika {j}"
        s_i = (s_i + s_ji) % q

    # Zajednički javni ključ: A = g^s = prod_j C_{j,0}.
    A = 1
    for C in commitments.values():
        A = (A * C[0]) % p
    return s_i, A
