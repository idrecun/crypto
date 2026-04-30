# pre prvog pokretanja: python zadatak8_setup.py
from kurs.network import Listener
import rsa
from zadatak8_keys import server_priv, server_pub

n, e = server_pub
d = server_priv

listener = Listener()
listener.start()
conn, _ = listener.accept()

with open("software.txt", "rb") as f:
    blob = f.read()

s = rsa.sign(blob, d, n)
conn.send((blob, s))

conn.close()
listener.close()
