# pokretanje učesnika i: python zadatak4.py <i> <n> <t> <s_i>
import sys
import secrets
import shamir
from shamir import q
from kurs.network import connect_mesh

i, n, t = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
s_i = int(sys.argv[4])

listener, peers = connect_mesh(i, n)

# Osvežavanje delova: svaki učesnik deli nulu (polinom stepena t sa slobodnim
# članom 0) i učesniku j šalje vrednost tog polinoma u j. Novi deo je stari plus
# zbir svih primljenih doprinosa. Tajna ostaje ista (svi dodati polinomi u nuli
# daju 0), ali stari delovi (vezani za stari polinom) postaju neupotrebljivi, pa
# napadač sa manje od praga starih delova ne može da ih dopuni novima.
zp = [0] + [secrets.randbelow(q) for _ in range(t)]
for j, conn in peers.items():
    conn.send(shamir.eval_poly(zp, j))
delta = shamir.eval_poly(zp, i)
for conn in peers.values():
    delta = (delta + conn.recv()) % q

for conn in peers.values():
    conn.close()
listener.close()
print(f"učesnik {i}: novi deo = {(s_i + delta) % q}", flush=True)
