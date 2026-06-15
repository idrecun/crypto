"""Lažiranje dokaza u pojednostavljenoj konstrukciji (bez jednakosti između
redova / povezanosti žica) i ispravka.

Kolo: w^3 + w + 5 = t. Pojednostavljeni proveravač proverava samo jednačinu
kola q(a+b) + (1-q)ab - c = 0 u svakom redu, što je ekvivalentno deljivosti
polinoma f sa z, ali ne i jednakosti između redova.
"""

# (a) Lažna tabela izvršavanja: svaki red je ispravna operacija, ali izlaz
# trećeg reda (w^3 = 8) NIJE prosleđen kao levi ulaz četvrtog (umesto 8 stoji 93).
#            q    a   b    c
trace = [(0,   2,  2,   4),
         (1,   2,  5,   7),
         (0,   4,  2,   8),
         (1,  93,  7, 100)]


def gate_ok(row):
    q, a, b, c = row
    return q * (a + b) + (1 - q) * a * b - c == 0


# Svi redovi zadovoljavaju jednačinu kola => f(x_i) = 0 u svim tačkama, pa je f
# deljivo sa z. „Dokazano" tvrđenje je t = c poslednjeg reda.
print(f"sve jednačine kola važe: {all(gate_ok(r) for r in trace)}")
print(f"„dokazano\" tvrđenje: w^3 + w + 5 = {trace[-1][3]} (netačno)")

# (b) Jednakosti između redova (povezanost žica) koje moraju da važe; redovi su
# 1-indeksirani kao u lekciji.
c = [r[3] for r in trace]
a = [r[1] for r in trace]
b = [r[2] for r in trace]
checks = [
    ("c(1) = a(3)  (w^2)", c[0], a[2]),
    ("c(2) = b(4)  (w+5)", c[1], b[3]),
    ("c(3) = a(4)  (w^3)", c[2], a[3]),
]
print("provera povezanosti žica:")
for name, lhs, rhs in checks:
    print(f"  {name}: {lhs} == {rhs} -> {lhs == rhs}")
print("ograničenje c(3) = a(4) hvata napad: 8 != 93.")
