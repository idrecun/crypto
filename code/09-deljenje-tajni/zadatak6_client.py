# pre pokretanja: bar t+1 učesnika (python zadatak6_server.py <i> 5 2)
import elgamal
from kurs.network import connect_retry

m = 123456789
indeksi = [1, 3, 5]

# Poveži se sa t+1 učesnika; svaki prvo šalje zajednički javni ključ A.
conns = {}
A = None
for i in indeksi:
    conns[i] = connect_retry(12344 + i)
    A = conns[i].recv()

# Šifruj poruku javnim ključem, pa od svakog učesnika prikupi delimični dešifrat.
R, c = elgamal.encrypt(m, A)
partials = {}
for i, conn in conns.items():
    conn.send(R)
    j, k_j = conn.recv()
    partials[j] = k_j
    conn.close()

m2 = elgamal.combine(R, c, partials)
print(f"dešifrovano: {m2}", flush=True)
print(f"ispravno: {m2 == m}", flush=True)
