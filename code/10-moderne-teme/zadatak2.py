import kzg
from kurs import pairing

q = pairing.q
G = pairing.G

# Setup je procureo: poznato je tau (toksični otpad). Objavljena je obaveza C_f
# na nepoznat polinom stepena najviše n (iz gen_zadaci.py).
tau = 808125594869607863673393924924
n = 8
C_f = (1740596318257679078439504556029, 797403434159898836096510084702)

# Javne parametre (a posebno g2 = (G, tau G)) možemo rekonstruisati iz tau.
g1, g2 = kzg.setup(tau, n)

# Napad: forsiramo dokaz da je f(5) = 1337, iako ne znamo polinom f. Provera je
# e(C_f - yG, G) = e(C_q, tau G - z G). Biramo C_q tako da jednakost važi za
# proizvoljno y: C_q = (tau - z)^{-1} (C_f - yG).
z, y = 5, 1337
C_q = pairing.mul(pow((tau - z) % q, -1, q), pairing.sub(C_f, pairing.mul(y, G)))
print(f"lažni dokaz f({z}) = {y} se prihvata: {kzg.verify(g2, C_f, z, y, C_q)}")

# Isti C_f se može „otvoriti" na bilo koju vrednost — dokaz ne znači ništa kad
# tau nije uništeno.
for y_lazno in (0, 42, 2 * y):
    C_q = pairing.mul(pow((tau - z) % q, -1, q), pairing.sub(C_f, pairing.mul(y_lazno, G)))
    print(f"  f({z}) = {y_lazno}: {kzg.verify(g2, C_f, z, y_lazno, C_q)}")
