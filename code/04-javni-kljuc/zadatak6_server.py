from kurs.network import Listener
from Crypto.Cipher import AES
import secrets
import rsa

listener = Listener()
listener.start()
conn, _ = listener.accept()

n, e = conn.recv()
aes_key = secrets.token_bytes(16)
c = rsa.encrypt(int.from_bytes(aes_key, "big"), e, n)
conn.send(c)

with open("data.txt", "rb") as f:
    data = f.read()

nonce = secrets.token_bytes(16)
aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
c, tag = aes.encrypt_and_digest(data)
conn.send((c, tag, nonce))

conn.close()
listener.close()
