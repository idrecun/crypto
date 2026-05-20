import secrets
from kurs import hash_obj, hash_to_bits


# Petocikl sa jednom tetivom (1-3). Hamiltonov ciklus: 0-1-2-3-4-0.
graf = {
    "n": 5,
    "E": [(0, 1), (1, 2), (2, 3), (3, 4), (4, 0), (1, 3)],
}
hamilton = [0, 1, 2, 3, 4]

K = 128


def adjacency(graf):
    n = graf["n"]
    A = [[0] * n for _ in range(n)]
    for u, v in graf["E"]:
        A[u][v] = 1
        A[v][u] = 1
    return A


def commit(bit, r):
    return hash_obj((bit, r))


def dokaz(graf, hamilton, k=K):
    n = graf["n"]
    A = adjacency(graf)
    rng = secrets.SystemRandom()
    iteracije = []
    for _ in range(k):
        sigma = list(range(n))
        rng.shuffle(sigma)
        B = [[0] * n for _ in range(n)]
        for u in range(n):
            for v in range(n):
                B[sigma[u]][sigma[v]] = A[u][v]
        r = [[secrets.token_bytes(16) for _ in range(n)] for _ in range(n)]
        com = [[commit(B[i][j], r[i][j]) for j in range(n)] for i in range(n)]
        iteracije.append((com, B, r, sigma))

    com_lista = [it[0] for it in iteracije]
    izazovi = hash_to_bits((graf, com_lista), k)

    otkrivanja = []
    for (_, B, r, sigma), e in zip(iteracije, izazovi):
        if e == 0:
            otkrivanja.append({"tip": 0, "B": B, "r": r, "sigma": sigma})
        else:
            H_perm = [sigma[v] for v in hamilton]
            ivice = []
            for i in range(n):
                a, b = H_perm[i], H_perm[(i + 1) % n]
                ivice.append((a, b, r[a][b]))
            otkrivanja.append({"tip": 1, "ivice": ivice})
    return {"com": com_lista, "otkrivanja": otkrivanja}


def provera(graf, proof):
    n = graf["n"]
    A = adjacency(graf)
    com_lista = proof["com"]
    otkrivanja = proof["otkrivanja"]
    k = len(com_lista)
    if k != len(otkrivanja):
        return False
    izazovi = hash_to_bits((graf, com_lista), k)
    for com, otkr, e in zip(com_lista, otkrivanja, izazovi):
        if e == 0:
            if otkr["tip"] != 0:
                return False
            B, r, sigma = otkr["B"], otkr["r"], otkr["sigma"]
            for i in range(n):
                for j in range(n):
                    if commit(B[i][j], r[i][j]) != com[i][j]:
                        return False
            for u in range(n):
                for v in range(n):
                    if B[sigma[u]][sigma[v]] != A[u][v]:
                        return False
        else:
            if otkr["tip"] != 1:
                return False
            ivice = otkr["ivice"]
            if len(ivice) != n:
                return False
            for a, b, r_ab in ivice:
                if commit(1, r_ab) != com[a][b]:
                    return False
            izlaz = {a: b for a, b, _ in ivice}
            if len(izlaz) != n or set(izlaz.values()) != set(range(n)):
                return False
            v = 0
            for _ in range(n):
                v = izlaz[v]
            if v != 0:
                return False
    return True


if __name__ == "__main__":
    proof = dokaz(graf, hamilton)
    print(f"validan dokaz: {provera(graf, proof)}")

    # Lažni dokaz: graf nema Hamiltonov ciklus, ali dokazivač pokušava.
    nelegalan = {"n": 4, "E": [(0, 1), (1, 2), (2, 0), (2, 3)]}
    lazni_proof = dokaz(nelegalan, [0, 1, 2, 3])
    print(f"lažan ciklus prolazi proveru: {provera(nelegalan, lazni_proof)}")
