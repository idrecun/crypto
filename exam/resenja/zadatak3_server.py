from kurs.network import Listener
import secrets
import zadatak3_rsa as rsa
from zadatak3_keys import client_pub

listener = Listener()
listener.start()
conn, _ = listener.accept()
challenge = secrets.token_bytes(32)
conn.send(challenge)
n, e = client_pub
ok = rsa.verify(challenge, conn.recv(), e, n)
conn.send(ok)
print("autentifikacija:", "uspesna" if ok else "neuspesna")
conn.close()
listener.close()
