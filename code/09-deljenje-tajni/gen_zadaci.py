"""Generiše konkretne vrednosti za zadatke 2 i 7 (napadi sa brojevima).

Koristi manju grupu (videti preambulu zadataka u lekciji). Pokrenuti iz
direktorijuma lekcije; izlaz se ubacuje u zadatak2/7.py i u tekst zadataka.
"""
import random as rnd
from kurs import hash_obj

p = 1267650600228229401496703217287
q = 633825300114114700748351608643
g = 2

rnd.seed(20260604)


def rand():
    return rnd.randrange(2, q)


def lagrange(indices, x=0):
    coeffs = {}
    for i in indices:
        num, den = 1, 1
        for j in indices:
            if j != i:
                num = (num * (x - j)) % q
                den = (den * (i - j)) % q
        coeffs[i] = (num * pow(den, -1, q)) % q
    return coeffs


def challenge(R, m):
    return int.from_bytes(hash_obj((R, m)), "big") % q


print("# === Zadatak 2: namestanje javnog kljuca (rogue key) ===")
others = [pow(g, rand(), p) for _ in range(4)]
print(f"others = {others}")

print("\n# === Zadatak 7: ponovljeno r_i jednog ucesnika ===")
m1, m2 = b"Zdravo, svete!", b"Vozdra, svete!"
signers, i = [1, 3, 5], 3
si = rand()
li = lagrange(signers)[i]
ri = rand()
c1_7 = challenge(pow(g, rand(), p), m1)
c2_7 = challenge(pow(g, rand(), p), m2)
print(f"signers = {signers}; i = {i}")
print(f"A_i = {pow(g, si, p)}")
print(f"c1 = {c1_7}")
print(f"pi1 = {(ri + c1_7 * li * si) % q}")
print(f"c2 = {c2_7}")
print(f"pi2 = {(ri + c2_7 * li * si) % q}")
print(f"# s_i (private) = {si}")
