from kurs import ec_n
import ec
import pedersen
import zadatak5


# 3x3 magični kvadrat — standardni Lo Shu kvadrat (magična konstanta 15).
magic = [
    [2, 7, 6],
    [9, 5, 1],
    [4, 3, 8],
]
N_SIDE = 3
N_CELLS = N_SIDE * N_SIDE
M = N_SIDE * (N_CELLS + 1) // 2  # 15


def grupe(n=N_SIDE):
    g = []
    for i in range(n):
        g.append([i * n + j for j in range(n)])          # vrste
    for j in range(n):
        g.append([i * n + j for i in range(n)])          # kolone
    g.append([i * n + i for i in range(n)])              # glavna dijagonala
    g.append([i * n + (n - 1 - i) for i in range(n)])    # sporedna dijagonala
    return g


def dokaz(magic, k=zadatak5.K):
    vrednosti = [v for row in magic for v in row]
    # P0 = (g^1, ..., g^N) — javan niz.
    P0 = [pedersen.commit(i + 1, 0) for i in range(N_CELLS)]
    # P1 — obaveze na vrednosti rešenja.
    rho = [pedersen.randomness() for _ in range(N_CELLS)]
    P1 = [pedersen.commit(vrednosti[i], rho[i]) for i in range(N_CELLS)]
    # π = "vrednost - 1" — permutacija koja od P0 pravi P1.
    pi = [vrednosti[i] - 1 for i in range(N_CELLS)]

    shuffle_proof = zadatak5.dokaz(P0, P1, pi, rho, k=k)
    # Za svaku grupu otkrij zbir randomness-a; verifikator proverava
    # da homomorfni proizvod obaveza odgovara obavezi na M.
    zbirovi = [sum(rho[i] for i in grupa) % ec_n for grupa in grupe()]
    return {"P1": P1, "shuffle": shuffle_proof, "zbirovi": zbirovi}


def provera(proof):
    P0 = [pedersen.commit(i + 1, 0) for i in range(N_CELLS)]
    P1 = proof["P1"]
    if not zadatak5.provera(P0, P1, proof["shuffle"]):
        return False
    zbirovi = proof["zbirovi"]
    grupa_lista = grupe()
    if len(zbirovi) != len(grupa_lista):
        return False
    for grupa, rho_zbir in zip(grupa_lista, zbirovi):
        prod = None
        for idx in grupa:
            prod = ec.add(prod, P1[idx])
        if prod != pedersen.commit(M, rho_zbir):
            return False
    return True


if __name__ == "__main__":
    proof = dokaz(magic)
    print(f"validan magični kvadrat: {provera(proof)}")

    # Lažan dokaz: nije magični kvadrat (ponovljena vrednost, zbirovi ne odgovaraju).
    lazan = [
        [2, 7, 6],
        [9, 5, 1],
        [4, 3, 9],
    ]
    lazni_proof = dokaz(lazan)
    print(f"lažan kvadrat prolazi proveru: {provera(lazni_proof)}")
