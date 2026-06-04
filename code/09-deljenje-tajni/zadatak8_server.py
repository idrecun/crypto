# pre prvog pokretanja: python zadatak8_setup.py
# pokretanje servera i: python zadatak8_server.py <i>   (npr. 1, 2, ..., 5)
import sys
import shamir
from shamir import g, p, q
from kurs.network import Listener
from zadatak8_keys import shares

i = int(sys.argv[1])
s_i = shares[i]
PORT = 12344 + i

listener = Listener(port=PORT)
listener.start()
print(f"server {i} sluša na portu {PORT}", flush=True)

while True:
    conn, _ = listener.accept()
    # Runda 1: server bira slučajno r_i i objavljuje R_i = g^{r_i}.
    signers = conn.recv()
    l_i = shamir.lagrange(signers)[i]
    r_i = shamir.rand_scalar()
    conn.send(pow(g, r_i, p))
    # Runda 2: na osnovu zajedničkog izazova c računa delimični potpis.
    c = conn.recv()
    conn.send((r_i + c * l_i * s_i) % q)
    conn.close()
