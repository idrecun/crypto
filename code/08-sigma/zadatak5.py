import secrets
from kurs import ec_n, hash_to_bits
import ec
import pedersen


def shuffle_rerandom(P, sigma, r):
    return [ec.add(P[sigma[i]], ec.mul(r[i], pedersen.H)) for i in range(len(sigma))]


def inverse_perm(sigma):
    inv = [0] * len(sigma)
    for i, x in enumerate(sigma):
        inv[x] = i
    return inv


def compose(f, g):
    return [f[g[i]] for i in range(len(g))]


K = 64


def dokaz(P0, P1, pi, rho, k=K):
    n = len(P0)
    pi_inv = inverse_perm(pi)
    rng = secrets.SystemRandom()
    iteracije = []
    for _ in range(k):
        sigma = list(range(n))
        rng.shuffle(sigma)
        r = [secrets.randbelow(ec_n) for _ in range(n)]
        C = shuffle_rerandom(P0, sigma, r)
        iteracije.append((C, sigma, r))

    com = [C for C, _, _ in iteracije]
    izazovi = hash_to_bits((P0, P1, com), k)

    otkrivanja = []
    for (_, sigma, r), e in zip(iteracije, izazovi):
        if e == 0:
            otkrivanja.append({"sigma": sigma, "r": r})
        else:
            # τ = π^{-1} ∘ σ, s[i] = r[i] - ρ[τ(i)]
            tau = compose(pi_inv, sigma)
            s = [(r[i] - rho[tau[i]]) % ec_n for i in range(n)]
            otkrivanja.append({"sigma": tau, "r": s})
    return {"com": com, "otkrivanja": otkrivanja}


def provera(P0, P1, proof):
    com = proof["com"]
    otkrivanja = proof["otkrivanja"]
    k = len(com)
    if k != len(otkrivanja):
        return False
    n = len(P0)
    izazovi = hash_to_bits((P0, P1, com), k)
    for C, otkr, e in zip(com, otkrivanja, izazovi):
        cilj = P0 if e == 0 else P1
        sigma = otkr["sigma"]
        r = otkr["r"]
        if sorted(sigma) != list(range(n)):
            return False
        if shuffle_rerandom(cilj, sigma, r) != C:
            return False
    return True


if __name__ == "__main__":
    n = 4
    vrednosti = [10, 20, 30, 40]
    rho0 = [pedersen.randomness() for _ in range(n)]
    P0 = [pedersen.commit(vrednosti[i], rho0[i]) for i in range(n)]

    pi = [2, 0, 3, 1]
    rho = [pedersen.randomness() for _ in range(n)]
    P1 = shuffle_rerandom(P0, pi, rho)

    proof = dokaz(P0, P1, pi, rho)
    print(f"validan dokaz mešanja: {provera(P0, P1, proof)}")

    # Lažni dokaz: P_random nije mešanje od P0.
    P_random = [pedersen.commit(99, pedersen.randomness()) for _ in range(n)]
    lazni = dokaz(P0, P_random, list(range(n)), [0] * n)
    print(f"lažno mešanje prolazi proveru: {provera(P0, P_random, lazni)}")
