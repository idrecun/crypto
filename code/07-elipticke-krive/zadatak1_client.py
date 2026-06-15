from kurs.network import ClientConnection
from hashlib import sha256
from Crypto.Cipher import AES
import secrets
import ecdh

conn = ClientConnection.connect()

a, A = ecdh.generate_keys()
conn.send(A)
B = conn.recv()
K = ecdh.shared_key(a, B)

aes_key = sha256(K[0].to_bytes(16, "big") + K[1].to_bytes(16, "big")).digest()

while True:
    m = input("> ")
    if m == "exit":
        break

    nonce = secrets.token_bytes(16)
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    c, tag = aes.encrypt_and_digest(m.encode())
    conn.send((c, tag, nonce))

conn.close()
