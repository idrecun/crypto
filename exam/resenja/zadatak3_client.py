from kurs.network import connect_retry
import zadatak3_rsa as rsa
from zadatak3_keys import client_priv

conn = connect_retry(12345)
challenge = conn.recv()
conn.send(rsa.sign(challenge, client_priv))
print("server:", "OK" if conn.recv() else "ODBIJEN")
conn.close()
