from kurs.network import Listener
from Crypto.Cipher import AES
from hashlib import sha256
import dh

listener = Listener()
listener.start()
conn, _ = listener.accept()

a, A = dh.generate_keys()
B = conn.recv()
conn.send(A)
k = dh.shared_key(a, B)

aes_key = sha256(k.to_bytes(192, 'big')).digest()

while True:
    c, tag, nonce = conn.recv()
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    m = aes.decrypt_and_verify(c, tag)
    print(m.decode())

conn.close()
listener.close()
