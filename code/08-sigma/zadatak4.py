import secrets
from kurs import hash_obj, hash_to_ints


# Pocetno stanje (S) i rešenje (R) sudokua.
S = [
    [5, 3, 0, 0, 7, 0, 0, 0, 0],
    [6, 0, 0, 1, 9, 5, 0, 0, 0],
    [0, 9, 8, 0, 0, 0, 0, 6, 0],
    [8, 0, 0, 0, 6, 0, 0, 0, 3],
    [4, 0, 0, 8, 0, 3, 0, 0, 1],
    [7, 0, 0, 0, 2, 0, 0, 0, 6],
    [0, 6, 0, 0, 0, 0, 2, 8, 0],
    [0, 0, 0, 4, 1, 9, 0, 0, 5],
    [0, 0, 0, 0, 8, 0, 0, 7, 9],
]
R = [
    [5, 3, 4, 6, 7, 8, 9, 1, 2],
    [6, 7, 2, 1, 9, 5, 3, 4, 8],
    [1, 9, 8, 3, 4, 2, 5, 6, 7],
    [8, 5, 9, 7, 6, 1, 4, 2, 3],
    [4, 2, 6, 8, 5, 3, 7, 9, 1],
    [7, 1, 3, 9, 2, 4, 8, 5, 6],
    [9, 6, 1, 5, 3, 7, 2, 8, 4],
    [2, 8, 7, 4, 1, 9, 6, 3, 5],
    [3, 4, 5, 2, 8, 6, 1, 7, 9],
]

K = 200
# 9 redova + 9 kolona + 9 kvadrata + 1 izazov za početne vrednosti.
NUM_IZAZOVA = 28


def commit(v, r):
    return hash_obj((v, r))


def ocekivane_celije(e):
    if e < 9:
        return [(e, j) for j in range(9)]
    if e < 18:
        j = e - 9
        return [(i, j) for i in range(9)]
    if e < 27:
        b = e - 18
        br, bc = (b // 3) * 3, (b % 3) * 3
        return [(br + di, bc + dj) for di in range(3) for dj in range(3)]
    return None  # izazov za početne vrednosti


def dokaz(S, R, k=K):
    rng = secrets.SystemRandom()
    iteracije = []
    for _ in range(k):
        pi = list(range(1, 10))
        rng.shuffle(pi)
        R_pi = [[pi[v - 1] for v in row] for row in R]
        r = [[secrets.token_bytes(16) for _ in range(9)] for _ in range(9)]
        com = [[commit(R_pi[i][j], r[i][j]) for j in range(9)] for i in range(9)]
        iteracije.append((com, R_pi, r, pi))

    com_lista = [it[0] for it in iteracije]
    izazovi = hash_to_ints((S, com_lista), k, NUM_IZAZOVA)

    otkrivanja = []
    for (_, R_pi, r, pi), e in zip(iteracije, izazovi):
        if e < 27:
            celije = [(i, j, R_pi[i][j], r[i][j]) for i, j in ocekivane_celije(e)]
            otkrivanja.append({"celije": celije})
        else:
            celije = [
                (i, j, R_pi[i][j], r[i][j])
                for i in range(9) for j in range(9) if S[i][j] != 0
            ]
            otkrivanja.append({"celije": celije, "pi": pi})
    return {"com": com_lista, "otkrivanja": otkrivanja}


def provera(S, proof):
    com_lista = proof["com"]
    otkrivanja = proof["otkrivanja"]
    k = len(com_lista)
    if k != len(otkrivanja):
        return False
    izazovi = hash_to_ints((S, com_lista), k, NUM_IZAZOVA)
    for com, otkr, e in zip(com_lista, otkrivanja, izazovi):
        celije = otkr["celije"]
        for i, j, v, ri in celije:
            if commit(v, ri) != com[i][j]:
                return False
        if e < 27:
            pozicije = [(i, j) for i, j, _, _ in celije]
            if pozicije != ocekivane_celije(e):
                return False
            if sorted(v for _, _, v, _ in celije) != list(range(1, 10)):
                return False
        else:
            pi = otkr.get("pi")
            if pi is None or sorted(pi) != list(range(1, 10)):
                return False
            pozicije = {(i, j) for i, j, _, _ in celije}
            ocekivane = {(i, j) for i in range(9) for j in range(9) if S[i][j] != 0}
            if pozicije != ocekivane:
                return False
            for i, j, v, _ in celije:
                if pi[S[i][j] - 1] != v:
                    return False
    return True


if __name__ == "__main__":
    proof = dokaz(S, R)
    print(f"validan dokaz: {provera(S, proof)}")

    # Lažni dokazivač menja jednu vrednost u rešenju.
    R_lose = [row[:] for row in R]
    R_lose[0][0] = 6
    lazni = dokaz(S, R_lose)
    print(f"lažno rešenje prolazi proveru: {provera(S, lazni)}")
