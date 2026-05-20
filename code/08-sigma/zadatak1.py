import secrets
from kurs import hash_obj, hash_to_ints

# Graf sa dva trougla koja dele granu — boji se sa 3 boje.
graf = {
    "n": 5,
    "E": [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 2)],
}
bojenje = [0, 1, 2, 0, 1]

K = 200


def commit(boja, r):
    return hash_obj((boja, r))


def dokaz(graf, bojenje, k=K):
    n = graf["n"]
    E = graf["E"]
    iteracije = []
    rng = secrets.SystemRandom()
    for _ in range(k):
        permutacija = [0, 1, 2]
        rng.shuffle(permutacija)
        r = [secrets.token_bytes(16) for _ in range(n)]
        boje = [permutacija[bojenje[v]] for v in range(n)]
        com = [commit(boje[v], r[v]) for v in range(n)]
        iteracije.append((com, boje, r))

    com_lista = [it[0] for it in iteracije]
    izazovi = hash_to_ints((graf, com_lista), k, len(E))

    otkrivanja = []
    for (_, boje, r), e in zip(iteracije, izazovi):
        u, v = E[e]
        otkrivanja.append((boje[u], r[u], boje[v], r[v]))
    return {"com": com_lista, "otkrivanja": otkrivanja}


def provera(graf, proof):
    E = graf["E"]
    com_lista = proof["com"]
    otkrivanja = proof["otkrivanja"]
    k = len(com_lista)
    if k != len(otkrivanja):
        return False
    izazovi = hash_to_ints((graf, com_lista), k, len(E))
    for com, (cu, ru, cv, rv), e in zip(com_lista, otkrivanja, izazovi):
        u, v = E[e]
        if cu == cv or cu not in (0, 1, 2) or cv not in (0, 1, 2):
            return False
        if commit(cu, ru) != com[u] or commit(cv, rv) != com[v]:
            return False
    return True


if __name__ == "__main__":
    proof = dokaz(graf, bojenje)
    print(f"k = {len(proof['com'])} iteracija")
    print(f"validan dokaz: {provera(graf, proof)}")

    # Lažni dokaz: nevalidno bojenje (čvorovi 0 i 1 imaju istu boju).
    lazno = [0, 0, 1, 2, 0]
    lazni_proof = dokaz(graf, lazno)
    print(f"lažno bojenje prolazi proveru: {provera(graf, lazni_proof)}")
