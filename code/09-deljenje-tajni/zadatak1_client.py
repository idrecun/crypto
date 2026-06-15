# pre pokretanja: python zadatak1_server.py
import shamir
from kurs.network import connect_retry


def fetch(indeksi):
    delovi = []
    for i in indeksi:
        conn = connect_retry(12345)
        conn.send(i)
        delovi.append(conn.recv())
        conn.close()
    return delovi


# Grupe bez učesnika 2 se međusobno slažu (ista, ispravna tajna)...
g134 = shamir.reconstruct(fetch([1, 3, 4]))
g345 = shamir.reconstruct(fetch([3, 4, 5]))
# ...dok grupe sa učesnikom 2 daju pogrešne i međusobno različite vrednosti.
g123 = shamir.reconstruct(fetch([1, 2, 3]))
g125 = shamir.reconstruct(fetch([1, 2, 5]))

print(f"grupe bez učesnika 2 se slažu: {g134 == g345}", flush=True)
print(f"grupe sa učesnikom 2 se razlikuju: {g123 != g125}", flush=True)
