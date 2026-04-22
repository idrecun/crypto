from kurs.network import Listener
from hashlib import sha256
from Crypto.Cipher import AES
import dh

e, E = dh.generate_keys()

listener = Listener()
listener.start()

conn1, _ = listener.accept()
conn2, _ = listener.accept()

A = conn1.recv()
B = conn2.recv()

conn1.send(E)
conn2.send(E)

shared1 = dh.shared_key(e, A)
shared2 = dh.shared_key(e, B)

aes_key1 = sha256(shared1.to_bytes(192, "big")).digest()
aes_key2 = sha256(shared2.to_bytes(192, "big")).digest()

while True:
    c, tag, nonce = conn1.recv()
    aes = AES.new(aes_key1, AES.MODE_GCM, nonce=nonce)
    m = aes.decrypt_and_verify(c, tag)
    print(m.decode())

    aes = AES.new(aes_key2, AES.MODE_GCM, nonce=nonce)
    c, tag = aes.encrypt_and_digest(m)
    conn2.send((c, tag, nonce))

conn1.close()
conn2.close()
listener.close()
