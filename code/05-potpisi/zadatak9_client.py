# pre prvog pokretanja: python zadatak9_setup.py
from kurs.network import ClientConnection
from kurs import dh_g, dh_p
import secrets
from zadatak9_keys import ana_priv

g = dh_g
p = dh_p
q = dh_p - 1

a = ana_priv
r = secrets.randbelow(q-1) + 1
R = pow(g, r, p)

conn = ClientConnection.connect()
conn.send(("ana", R))
c = conn.recv()
s = (r + a * c) % q
conn.send(s)
conn.close()
