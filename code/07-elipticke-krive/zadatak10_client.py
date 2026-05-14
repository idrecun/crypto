# pre prvog pokretanja: python zadatak10_setup.py
from kurs.network import ClientConnection
from hashlib import sha256
from Crypto.Cipher import AES
import secrets
import ecdh
import ec_schnorr
from zadatak10_keys import client_priv, server_pub


def point_bytes(P):
    return P[0].to_bytes(16, "big") + P[1].to_bytes(16, "big")


conn = ClientConnection.connect()

a, A_dh = ecdh.generate_keys()
R_c, s_c = ec_schnorr.sign(point_bytes(A_dh), client_priv)
conn.send((A_dh, R_c, s_c))

B_dh, R_s, s_s = conn.recv()
if not ec_schnorr.verify(point_bytes(B_dh), R_s, s_s, server_pub):
    print("serverov potpis nije validan")
    conn.close()
    exit()

K = ecdh.shared_key(a, B_dh)
aes_key = sha256(point_bytes(K)).digest()

while True:
    m = input("> ")
    if m == "exit":
        break

    nonce = secrets.token_bytes(16)
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    c, tag = aes.encrypt_and_digest(m.encode())
    conn.send((c, tag, nonce))

conn.close()
