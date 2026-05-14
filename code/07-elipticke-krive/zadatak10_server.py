# pre prvog pokretanja: python zadatak10_setup.py
from kurs.network import Listener
from hashlib import sha256
from Crypto.Cipher import AES
import ecdh
import ec_schnorr
from zadatak10_keys import server_priv, client_pub


def point_bytes(P):
    return P[0].to_bytes(16, "big") + P[1].to_bytes(16, "big")


listener = Listener()
listener.start()
conn, _ = listener.accept()

A_dh, R_c, s_c = conn.recv()
if not ec_schnorr.verify(point_bytes(A_dh), R_c, s_c, client_pub):
    print("klijentov potpis nije validan")
    conn.close()
    listener.close()
    exit()

b, B_dh = ecdh.generate_keys()
R_s, s_s = ec_schnorr.sign(point_bytes(B_dh), server_priv)
conn.send((B_dh, R_s, s_s))

K = ecdh.shared_key(b, A_dh)
aes_key = sha256(point_bytes(K)).digest()

while True:
    c, tag, nonce = conn.recv()
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    m = aes.decrypt_and_verify(c, tag)
    print(m.decode())

conn.close()
listener.close()
