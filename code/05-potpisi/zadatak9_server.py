# pre prvog pokretanja: python zadatak9_setup.py
from kurs.network import Listener
from kurs import dh_g, dh_p
import secrets
from zadatak9_keys import users

g = dh_g
p = dh_p
q = dh_p - 1

listener = Listener()
listener.start()

while True:
    conn, _ = listener.accept()
    username, R = conn.recv()
    A = users[username]
    c = secrets.randbelow(q)
    conn.send(c)
    s = conn.recv()
    if pow(g, s, p) == (R * pow(A, c, p)) % p:
        print(f"prijavljen: {username}")
    else:
        print(f"odbijeno: {username}")
    conn.close()
