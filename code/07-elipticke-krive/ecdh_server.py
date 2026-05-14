from kurs.network import Listener
import ecdh

a, A = ecdh.generate_keys()

listener = Listener()
listener.start()

conn, _ = listener.accept()

conn.send(A)
B = conn.recv()
shared = ecdh.shared_key(a, B)
print(f"Shared key: {shared}")

conn.close()
listener.close()
