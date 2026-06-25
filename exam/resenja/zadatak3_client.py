from kurs.network import connect_retry
import zadatak3_rsa as rsa
from zadatak3_keys import client_priv

conn = connect_retry(12345)
challenge = conn.recv()
d, n = client_priv
conn.send(rsa.sign(challenge, d, n))
print("server:", "OK" if conn.recv() else "ODBIJEN")
conn.close()
