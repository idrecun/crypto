import shamir
import feldman
from shamir import q

# Vi ste delilac (prag 3 od 5) i želite da sabotirate učesnika 2. Bira se
# ispravan polinom, ali se učesniku 2 pošalje pokvaren deo.
s = 1234567890
coeffs = shamir.random_poly(s, t=2)
parts = {i: shamir.eval_poly(coeffs, i) for i in range(1, 6)}
parts[2] = (parts[2] + 12345) % q  # sabotiran deo

# Grupe bez učesnika 2 rekonstruišu ispravnu tajnu...
g134 = shamir.reconstruct([(1, parts[1]), (3, parts[3]), (4, parts[4])])
# ...dok grupe sa učesnikom 2 rekonstruišu pogrešne (i međusobno različite) vrednosti.
g123 = shamir.reconstruct([(1, parts[1]), (2, parts[2]), (3, parts[3])])
g125 = shamir.reconstruct([(1, parts[1]), (2, parts[2]), (5, parts[5])])

print(f"grupa 1,3,4 (bez 2): tačno = {g134 == s}")
print(f"grupa 1,2,3 (sa 2):  tačno = {g123 == s}")
print(f"grupe sa učesnikom 2 daju različite tajne: {g123 != g125}")
# U običnom Šamirovom deljenju učesnik 2 vidi samo broj i ne može da utvrdi grešku.

# Feldmanova odbrana: delilac objavljuje obaveze koeficijenata polinoma, pa
# svaki učesnik može da proveri svoj deo. Sabotiran deo ne prolazi proveru.
C = feldman.commit(coeffs)
print(f"deo učesnika 2 prolazi Feldmanovu proveru: {feldman.verify((2, parts[2]), C)}")
print(f"delovi ostalih učesnika prolaze proveru: "
      f"{all(feldman.verify((i, parts[i]), C) for i in [1, 3, 4, 5])}")
# Pošto svi delovi moraju da zadovolje iste obaveze (jedan polinom stepena t),
# delilac više ne može da napravi delove tako da različite grupe dobiju
# različite tajne.
