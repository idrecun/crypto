import secrets
import shamir
from shamir import q

n, t = 5, 2
s = 1234567890
old = dict(shamir.share(s, t, n))  # {i: s_i}


def refresh(shares):
    """Osvežavanje delova: učesnici zajednički generišu deljenje nule (svaki bira
    polinom stepena t sa slobodnim članom 0) i svaki dodaje primljeni deo na svoj
    postojeći. Tajna s ostaje ista jer dodati polinom u nuli ima vrednost 0."""
    zero_polys = [[0] + [secrets.randbelow(q) for _ in range(t)] for _ in shares]
    new = {}
    for j in shares:
        delta = sum(shamir.eval_poly(zp, j) for zp in zero_polys) % q
        new[j] = (shares[j] + delta) % q
    return new


new = refresh(old)

# Novi delovi i dalje rekonstruišu istu tajnu.
print(f"novi delovi rekonstruišu istu tajnu: "
      f"{shamir.reconstruct(list(new.items())[:3]) == s}")

# Stari delovi su sada beskorisni: pripadaju starom polinomu, pa kombinovani sa
# novim delovima ne daju tajnu. Napadač koji je prikupio manje od praga starih
# delova ne može da ih dopuni novima.
mixed = [(1, old[1]), (2, new[2]), (3, new[3])]
print(f"mešanje starog i novih delova daje tajnu: "
      f"{shamir.reconstruct(mixed) == s}")
