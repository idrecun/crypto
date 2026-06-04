import secrets
from kurs import dh_g, dh_p

# Radimo u cikličnoj podgrupi reda q grupe Z_p^*. Pošto je p bezbedan prost broj
# (p = 2q + 1), broj q je prost, a g = 2 (kvadratni ostatak) generiše podgrupu
# reda q. Delovi tajne i koeficijenti polinoma su skalari u prostom polju Z_q,
# što je neophodno da bi Lagranžova interpolacija bila dobro definisana.
p = dh_p
q = (dh_p - 1) // 2
g = dh_g


def rand_scalar():
    return secrets.randbelow(q - 1) + 1


def random_poly(s, t):
    """Slučajan polinom stepena t sa slobodnim članom s (predstavljen
    koeficijentima [s, a_1, ..., a_t])."""
    return [s] + [secrets.randbelow(q) for _ in range(t)]


def eval_poly(coeffs, x):
    """Vrednost polinoma u tački x (Hornerova šema, mod q)."""
    y = 0
    for c in reversed(coeffs):
        y = (y * x + c) % q
    return y


def share(s, t, n):
    """Podeli tajnu s na n delova, pri čemu je za rekonstrukciju potrebno t+1
    delova. Vraća listu delova (i, s_i)."""
    coeffs = random_poly(s, t)
    return [(i, eval_poly(coeffs, i)) for i in range(1, n + 1)]


def lagrange(indices, x=0):
    """Lagranžovi koeficijenti l_i(x) za date indekse učesnika (mod q)."""
    coeffs = {}
    for i in indices:
        num, den = 1, 1
        for j in indices:
            if j != i:
                num = (num * (x - j)) % q
                den = (den * (i - j)) % q
        coeffs[i] = (num * pow(den, -1, q)) % q
    return coeffs


def reconstruct(parts):
    """Rekonstruiši tajnu iz delova (i, s_i) Lagranžovom interpolacijom u 0."""
    coeffs = lagrange([i for i, _ in parts])
    return sum(coeffs[i] * s_i for i, s_i in parts) % q


if __name__ == "__main__":
    s = 1234567890
    parts = share(s, t=2, n=5)
    print(f"tajna: {s}")
    print(f"rekonstrukcija iz delova 1,2,3: {reconstruct(parts[:3]) == s}")
    print(f"rekonstrukcija iz delova 2,4,5: {reconstruct([parts[1], parts[3], parts[4]]) == s}")
    print(f"rekonstrukcija iz samo 2 dela:  {reconstruct(parts[:2]) == s}")
