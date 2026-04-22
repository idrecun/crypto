from kurs.network import ClientConnection
from hashlib import sha256
from Crypto.Cipher import AES
import secrets
import elgamal

conn = ClientConnection.connect()

server_pk = conn.recv()

aes_key = secrets.token_bytes(16)
c1, c2 = elgamal.encrypt(int.from_bytes(aes_key, "big"), server_pk)
conn.send((c1, c2))

while True:
    m = input("> ")
    if m == "exit":
        break

    nonce = secrets.token_bytes(16)
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    c, tag = aes.encrypt_and_digest(m.encode())
    conn.send((c, tag, nonce))

conn.close()
