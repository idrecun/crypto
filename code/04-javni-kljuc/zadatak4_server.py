from kurs.network import Listener
from Crypto.Cipher import AES
from hashlib import sha256
import elgamal

listener = Listener()
listener.start()
conn, _ = listener.accept()

sk, pk = elgamal.generate_keys()
conn.send(pk)

c1, c2 = conn.recv()
aes_key = elgamal.decrypt(c1, c2, sk).to_bytes(16, "big")

while True:
    c, tag, nonce = conn.recv()
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    m = aes.decrypt_and_verify(c, tag)
    print(m.decode())

conn.close()
listener.close()
