from kurs.network import ClientConnection
import ecdh

b, B = ecdh.generate_keys()

conn = ClientConnection.connect()

A = conn.recv()
conn.send(B)

shared = ecdh.shared_key(b, A)
print(f"Shared key: {shared}")

conn.close()
