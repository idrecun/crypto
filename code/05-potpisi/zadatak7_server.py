# pre prvog pokretanja: python zadatak7_setup.py
from kurs.network import Listener
from kurs import dh_g, dh_p
from hashlib import sha256
from Crypto.Cipher import AES
import secrets
import schnorr
from zadatak7_keys import server_priv, client_pub

g = dh_g
p = dh_p

listener = Listener()
listener.start()
conn, _ = listener.accept()

A_dh, R_c, s_c = conn.recv()
if not schnorr.verify(A_dh.to_bytes(192, "big"), R_c, s_c, client_pub):
    print("klijentov potpis nije validan")
    conn.close()
    listener.close()
    exit()

b = secrets.randbelow(p-2) + 1
B_dh = pow(g, b, p)
R_s, s_s = schnorr.sign(B_dh.to_bytes(192, "big"), server_priv)
conn.send((B_dh, R_s, s_s))

k = pow(A_dh, b, p)
aes_key = sha256(k.to_bytes(192, "big")).digest()

while True:
    c, tag, nonce = conn.recv()
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    m = aes.decrypt_and_verify(c, tag)
    print(m.decode())

conn.close()
listener.close()
