from kurs.network import ClientConnection
import dh

b, B = dh.generate_keys()

conn = ClientConnection.connect()

A = conn.recv()
conn.send(B)

shared = dh.shared_key(b, A)
print(f"Shared key: {shared}")

conn.close()
