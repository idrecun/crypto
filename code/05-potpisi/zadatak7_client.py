# pre prvog pokretanja: python zadatak7_setup.py
from kurs.network import ClientConnection
from kurs import dh_g, dh_p
from hashlib import sha256
from Crypto.Cipher import AES
import secrets
import schnorr
from zadatak7_keys import client_priv, server_pub

g = dh_g
p = dh_p

conn = ClientConnection.connect()

a = secrets.randbelow(p-2) + 1
A_dh = pow(g, a, p)
R_c, s_c = schnorr.sign(A_dh.to_bytes(192, "big"), client_priv)
conn.send((A_dh, R_c, s_c))

B_dh, R_s, s_s = conn.recv()
if not schnorr.verify(B_dh.to_bytes(192, "big"), R_s, s_s, server_pub):
    print("serverov potpis nije validan")
    conn.close()
    exit()

k = pow(B_dh, a, p)
aes_key = sha256(k.to_bytes(192, "big")).digest()

while True:
    m = input("> ")
    if m == "exit":
        break

    nonce = secrets.token_bytes(16)
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    c, tag = aes.encrypt_and_digest(m.encode())
    conn.send((c, tag, nonce))

conn.close()
