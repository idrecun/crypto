import secrets

import bls
from kurs import pairing, hash_obj

q = pairing.q
G = pairing.G

# Javni ključevi ostalih učesnika multipotpisa (iz gen_zadaci.py).
others = [(3253197710747319552652331051736, 2600547458541519107537085876347),
          (493875947817263770200857539721, 1005457789544420329373492633801),
          (4398077327025274074111996186478, 4032416314574447102788999321266),
          (2488539465432787523312532108876, 633500602060898915500471203495)]

# Napad: vi se pridružujete poslednji i vidite tuđe ključeve. Birate x i
# namestite svoj ključ A_n = xG - sum(others). Tada je zajednički ključ
# apk = sum(others) + A_n = xG, čiji tajni ključ (x) jedino vi znate.
x = 1337
acc = None
for Ai in others:
    acc = pairing.add(acc, Ai)
A_n = pairing.sub(pairing.mul(x, G), acc)
apk = bls.aggregate_pubkey(others + [A_n])
print(f"zajednički ključ je tačno xG: {apk == pairing.mul(x, G)}")

# Sada sami proizvodite validan multipotpis cele grupe za proizvoljnu poruku
# (potpis sa tajnim ključem x), iako ostali učesnici ništa nisu potpisali.
m = b"Napadacu pripada sav novac."
S = pairing.mul(x, pairing.hash_to_point(m))
print(f"lažni multipotpis grupe validan: {bls.verify_multisig(apk, m, S)}")


# Odbrana: svaki učesnik uz svoj ključ prilaže Šnorov dokaz poznavanja tajnog
# ključa (diskretnog logaritma baze G).
def prove_knowledge(a):
    A = pairing.mul(a % q, G)
    k = secrets.randbelow(q - 1) + 1
    K = pairing.mul(k, G)
    e = int.from_bytes(hash_obj((A, K)), "big") % q
    return K, (k + e * a) % q


def verify_knowledge(A, proof):
    K, z = proof
    e = int.from_bytes(hash_obj((A, K)), "big") % q
    return pairing.mul(z, G) == pairing.add(K, pairing.mul(e, A))


# Pošten učesnik (koji zna svoj tajni ključ) može da napravi dokaz...
a = secrets.randbelow(q - 1) + 1
print(f"pošten dokaz se prihvata: {verify_knowledge(pairing.mul(a, G), prove_knowledge(a))}")
# ...ali vi ne znate diskretni logaritam vrednosti A_n (jer ne znate tajne
# ključeve ostalih učesnika). Dokaz napravljen pomoću x dokazuje znanje za xG,
# a ne za A_n, pa provera pada.
print(f"lažni dokaz za A_n se prihvata: {verify_knowledge(A_n, prove_knowledge(x))}")
