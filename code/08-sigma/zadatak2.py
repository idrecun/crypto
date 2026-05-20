import secrets
from kurs import hash_to_bits


def normalize(n, edges):
    norm = sorted(tuple(sorted(e)) for e in edges if e[0] != e[1])
    return (n, tuple(norm))


def permute(graf, sigma):
    n, E = graf
    return normalize(n, [(sigma[u], sigma[v]) for u, v in E])


def inverse(sigma):
    inv = [0] * len(sigma)
    for i, x in enumerate(sigma):
        inv[x] = i
    return inv


def compose(f, g):
    return [f[g[i]] for i in range(len(g))]


# G0 = 4-cikl (0-1-2-3-0). G1 = permutacija od G0 pomoću φ.
G0 = normalize(4, [(0, 1), (1, 2), (2, 3), (3, 0)])
phi = [2, 0, 3, 1]
G1 = permute(G0, phi)

K = 128


def dokaz(G0, G1, phi, k=K):
    n = G0[0]
    rng = secrets.SystemRandom()
    iteracije = []
    for _ in range(k):
        sigma = list(range(n))
        rng.shuffle(sigma)
        C = permute(G0, sigma)
        iteracije.append((C, sigma))

    com = [C for C, _ in iteracije]
    izazovi = hash_to_bits((G0, G1, com), k)

    otkrivanja = []
    for (_, sigma), e in zip(iteracije, izazovi):
        # σ: G0 → C, dakle σ^{-1}: C → G0 i φ∘σ^{-1}: C → G1.
        iso = inverse(sigma) if e == 0 else compose(phi, inverse(sigma))
        otkrivanja.append(iso)
    return {"com": com, "otkrivanja": otkrivanja}


def provera(G0, G1, proof):
    com = proof["com"]
    otkrivanja = proof["otkrivanja"]
    k = len(com)
    if len(otkrivanja) != k:
        return False
    izazovi = hash_to_bits((G0, G1, com), k)
    for C, iso, e in zip(com, otkrivanja, izazovi):
        cilj = G0 if e == 0 else G1
        if permute(C, iso) != cilj:
            return False
    return True


if __name__ == "__main__":
    proof = dokaz(G0, G1, phi)
    print(f"G0 = {G0}")
    print(f"G1 = {G1}")
    print(f"validan dokaz: {provera(G0, G1, proof)}")

    # Pokušaj falsifikata: dokazivač zapravo ne zna izomorfizam između
    # G0 i ne-izomorfnog grafa G_fake.
    G_fake = normalize(4, [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3)])
    # "Lažni" dokazivač pretpostavlja identitet — proverava se da je neuspeh.
    lazni_proof = dokaz(G0, G_fake, list(range(4)))
    print(f"lažan iso prolazi proveru: {provera(G0, G_fake, lazni_proof)}")
