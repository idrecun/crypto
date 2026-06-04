# pre pokretanja: python zadatak5_setup.py, pa pokrenuti bar t+1 servera
from kurs.network import ClientConnection
import elgamal
from zadatak5_keys import A

m = 123456789
R, c = elgamal.encrypt(m, A)

# Klijent kontaktira t+1 = 3 servera; svaki vraća svoj delimični dešifrat.
indeksi = [1, 3, 5]
partials = {}
for i in indeksi:
    conn = ClientConnection.connect(port=12344 + i)
    conn.send(R)
    j, k_j = conn.recv()
    partials[j] = k_j
    conn.close()

m2 = elgamal.combine(R, c, partials)
print(f"dešifrovano: {m2}")
print(f"ispravno: {m2 == m}")
