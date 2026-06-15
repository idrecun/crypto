# pokretanje delioca: python zadatak1_server.py
import shamir
from shamir import q
from kurs.network import Listener

# Delilac (prag 3 od 5) sabotira učesnika 2: bira ispravan polinom, ali učesniku
# 2 deli pokvaren deo. Grupe bez učesnika 2 rekonstruišu ispravnu tajnu, dok
# svaka grupa sa učesnikom 2 dobija pogrešnu vrednost. U običnom Šamirovom
# deljenju učesnik 2 vidi samo broj i ne može da utvrdi da je deo neispravan.
s, t, n = 1234567890, 2, 5
coeffs = shamir.random_poly(s, t)
parts = {i: shamir.eval_poly(coeffs, i) for i in range(1, n + 1)}
parts[2] = (parts[2] + 12345) % q  # sabotiran deo učesnika 2

listener = Listener()
listener.start()
print(f"delilac sluša; tajna = {s} (učesnik 2 je sabotiran)", flush=True)
while True:
    conn, _ = listener.accept()
    i = conn.recv()
    conn.send((i, parts[i]))
    conn.close()
