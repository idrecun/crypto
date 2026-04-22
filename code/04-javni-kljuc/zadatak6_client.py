from kurs.network import ClientConnection
from Crypto.Cipher import AES
import secrets
import rsa

conn = ClientConnection.connect()

d, (n, e) = rsa.generate_keys()
conn.send((n, e))

c = conn.recv()
aes_key = rsa.decrypt(c, d, n).to_bytes(16, "big")

c, tag, nonce = conn.recv()
aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
data = aes.decrypt_and_verify(c, tag)

with open("received_data.txt", "wb") as f:
    f.write(data)

conn.close()
