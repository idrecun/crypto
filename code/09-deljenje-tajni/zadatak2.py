import secrets
from kurs import hash_obj

p = 1267650600228229401496703217287
q = 633825300114114700748351608643
g = 2

# Doprinosi ostalih učesnika (iz gen_zadaci.py).
others = [526504585288905119860786968747, 751429976279136810775446160289,
          1174038313191067889758460100673, 646711060212620438228628540866]

# Napad: vi objavljujete poslednji i birate x. Namestite svoj doprinos C_n tako
# da zajednički javni ključ A = prod C_i bude tačno g^x.
x = 1337
C = 1
for Ci in others:
    C = (C * Ci) % p
C_n = (pow(g, x, p) * pow(C, -1, p)) % p
A = (C * C_n) % p
print(f"zajednički ključ je tačno g^x: {A == pow(g, x, p)}")
# Jedino vi znate tajni ključ x koji odgovara ovom javnom ključu.


# Odbrana: svaki učesnik uz svoj doprinos prilaže Šnorov dokaz poznavanja
# eksponenta (g^a = C_i).
def prove_knowledge(a):
    C = pow(g, a, p)
    k = secrets.randbelow(q - 1) + 1
    K = pow(g, k, p)
    e = int.from_bytes(hash_obj((C, K)), "big") % q
    return K, (k + e * a) % q


def verify_knowledge(C, proof):
    K, z = proof
    e = int.from_bytes(hash_obj((C, K)), "big") % q
    return pow(g, z, p) == (K * pow(C, e, p)) % p


# Pošten učesnik (koji zna svoj eksponent) može da napravi dokaz...
a = secrets.randbelow(q - 1) + 1
print(f"pošten dokaz se prihvata: {verify_knowledge(pow(g, a, p), prove_knowledge(a))}")
# ...ali vi ne znate diskretni logaritam vrednosti C_n. Dokaz napravljen pomoću
# poznatog x dokazuje znanje za g^x, a ne za C_n, pa provera pada.
print(f"lažni dokaz za C_n se prihvata: {verify_knowledge(C_n, prove_knowledge(x))}")
