# pre prvog pokretanja: python zadatak5_setup.py
# pokretanje servera i: python zadatak5_server.py <i>   (npr. 1, 2, ..., 5)
import sys
from kurs.network import Listener
import elgamal
from zadatak5_keys import shares

i = int(sys.argv[1])
s_i = shares[i]
PORT = 12344 + i

listener = Listener(port=PORT)
listener.start()
print(f"server {i} sluša na portu {PORT}", flush=True)

while True:
    conn, _ = listener.accept()
    R = conn.recv()
    # Server objavljuje samo svoj delimični dešifrat k_i = R^{s_i}.
    conn.send((i, elgamal.partial_decrypt(R, s_i)))
    conn.close()
