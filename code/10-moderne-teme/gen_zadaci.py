"""Generiše konkretne vrednosti za zadatke sa brojevima (BLS rogue key, KZG
toksični otpad, KZG homomorfizam) i podatke za Lamportov zadatak.

Pokrenuti iz direktorijuma lekcije:

    ../.venv/bin/python gen_zadaci.py

Male vrednosti se ispisuju radi prepisivanja u zadatke i tekst lekcije; obimni
podaci za Lamporta se upisuju u zadatak5_data.py. Svaki napad se ovde i proverava,
tako da su objavljene vrednosti sigurno konzistentne sa rešenjima.
"""

import random as rnd

import bls
import kzg
import lamport
from kurs import pairing, hash_obj

q = pairing.q
G = pairing.G

rnd.seed(20260615)


def rand_scalar():
    return rnd.randrange(2, q)


# === Zadatak 1: BLS rogue-key napad ===
print("# === Zadatak 1: BLS rogue-key napad ===")
secrets1 = [rand_scalar() for _ in range(4)]
others = [bls.keygen(a) for a in secrets1]
print(f"others = {others}")

# Provera napada: poslednji učesnik bira x i namešta A5 = xG - sum others.
x = 1337
acc = None
for Ai in others:
    acc = pairing.add(acc, Ai)
A5 = pairing.sub(pairing.mul(x, G), acc)
apk = pairing.add(acc, A5)
m_forge = b"Napadacu pripada sav novac."
S = pairing.mul(x, pairing.hash_to_point(m_forge))
assert apk == pairing.mul(x, G)
assert bls.verify_multisig(apk, m_forge, S)
print(f"# (provera) lažni multipotpis grupe validan: {bls.verify_multisig(apk, m_forge, S)}")


# === Zadatak 2: KZG toksični otpad ===
print("\n# === Zadatak 2: KZG toksicni otpad (procurelo tau) ===")
tau = rand_scalar()
n = 8
g1, g2 = kzg.setup(tau, n)
# Tajni polinom nekog drugog učesnika (napadač ga ne zna, vidi samo obavezu C_f).
f_secret = [rand_scalar() for _ in range(n + 1)]
C_f = kzg.commit(g1, f_secret)
print(f"tau = {tau}")
print(f"n = {n}")
print(f"C_f = {C_f}")

# Provera napada: forsiraj dokaz da je f(5) = 1337 (lažno) koristeći tau.
z_fake, y_fake = 5, 1337
proof = pairing.mul(pow((tau - z_fake) % q, -1, q), pairing.sub(C_f, pairing.mul(y_fake, G)))
assert kzg.verify(g2, C_f, z_fake, y_fake, proof)
assert kzg.poly_eval(f_secret, z_fake) != y_fake
print(f"# (provera) lažni dokaz f({z_fake})={y_fake} se prihvata: {kzg.verify(g2, C_f, z_fake, y_fake, proof)}")


# === Zadatak 3: KZG homomorfizam ===
print("\n# === Zadatak 3: KZG homomorfizam ===")
tau3 = rand_scalar()
n3 = 6
g1_3, g2_3 = kzg.setup(tau3, n3)
f_poly = [rand_scalar() for _ in range(n3 + 1)]
g_poly = [rand_scalar() for _ in range(n3 + 1)]
z3 = 9
C_f3 = kzg.commit(g1_3, f_poly)
C_g3 = kzg.commit(g1_3, g_poly)
proof_f, y_f = kzg.prove(g1_3, f_poly, z3)
proof_g, y_g = kzg.prove(g1_3, g_poly, z3)
print(f"# javni parametri (G, tau G):")
print(f"g2 = {g2_3}")
print(f"C_f = {C_f3}")
print(f"C_g = {C_g3}")
print(f"z = {z3}")
print(f"y_f = {y_f}; proof_f = {proof_f}")
print(f"y_g = {y_g}; proof_g = {proof_g}")
# Provera: agregacija u jednu obavezu i jedan dokaz za f+g.
C_sum = pairing.add(C_f3, C_g3)
proof_sum = pairing.add(proof_f, proof_g)
y_sum = (y_f + y_g) % q
assert kzg.verify(g2_3, C_sum, z3, y_sum, proof_sum)
print(f"# (provera) jedan dokaz za (f+g)({z3})={y_sum} validan: {kzg.verify(g2_3, C_sum, z3, y_sum, proof_sum)}")


# === Zadatak 5: Lamport, ponovljeni ključ ===
print("\n# === Zadatak 5: Lamport, ponovljeni kljuc ===")
# Determinističko generisanje ključa (seedovani RNG umesto secrets).
sk = [(rnd.randbytes(lamport.N // 8), rnd.randbytes(lamport.N // 8)) for _ in range(lamport.N)]
pk = [(lamport.h(xv), lamport.h(yv)) for (xv, yv) in sk]

target = b"Kvantni pozdrav!"
target_bits = lamport.bits(lamport.h(target))

# Skup verovatnih poruka; pohlepno biramo podskup koji za svaku poziciju pokriva
# bit koji target zahteva.
pool = [
    b"Postovani, saljem vam izvestaj.",
    b"Sastanak je zakazan za ponedeljak.",
    b"Racun je izmiren u celosti.",
    b"Molim vas potvrdite prijem.",
    b"Dokument je u prilogu.",
    b"Hvala na saradnji.",
    b"Termin se pomera za utorak.",
    b"Ugovor stupa na snagu odmah.",
    b"Verzija 2.0 je objavljena.",
    b"Svi testovi su prosli.",
] + [b"Poruka broj %d." % k for k in range(40)]

uncovered = set(range(lamport.N))
chosen = []
for msg in pool:
    if not uncovered:
        break
    mb = lamport.bits(lamport.h(msg))
    gain = {i for i in uncovered if mb[i] == target_bits[i]}
    if gain:
        chosen.append(msg)
        uncovered -= gain
assert not uncovered, "skup poruka ne pokriva ciljnu poruku"

signatures = [lamport.sign(sk, msg) for msg in chosen]
print(f"broj potpisanih poruka: {len(chosen)}")
for msg in chosen:
    print(f"  {msg.decode()}")

# Provera napada: sklopi potpis za target iz otkrivenih vrednosti.
forged = [None] * lamport.N
for msg, sig in zip(chosen, signatures):
    mb = lamport.bits(lamport.h(msg))
    for i in range(lamport.N):
        if mb[i] == target_bits[i]:
            forged[i] = sig[i]
assert all(v is not None for v in forged)
assert lamport.verify(pk, target, forged)
print(f"# (provera) sklopljen potpis za '{target.decode()}' validan: {lamport.verify(pk, target, forged)}")

# Upiši obimne podatke u zadatak5_data.py.
with open("zadatak5_data.py", "w") as fp:
    fp.write('"""Podaci za zadatak 5 (generisano iz gen_zadaci.py). Ne menjati rucno."""\n\n')
    fp.write("# Javni kljuc: lista parova (h(x_i), h(y_i)).\n")
    fp.write("pk = [\n")
    for hx, hy in pk:
        fp.write(f"    (bytes.fromhex('{hx.hex()}'), bytes.fromhex('{hy.hex()}')),\n")
    fp.write("]\n\n")
    fp.write("# Potpisane poruke i njihovi potpisi (potpis = lista otkrivenih vrednosti).\n")
    fp.write("messages = [\n")
    for msg in chosen:
        fp.write(f"    {msg!r},\n")
    fp.write("]\n\n")
    fp.write("signatures = [\n")
    for sig in signatures:
        fp.write("    [" + ", ".join(f"bytes.fromhex('{v.hex()}')" for v in sig) + "],\n")
    fp.write("]\n")
print("# podaci upisani u zadatak5_data.py")
