from kurs.network import Listener
import dh

a, A = dh.generate_keys()

listener = Listener()
listener.start()

conn, _ = listener.accept()

conn.send(A)
B = conn.recv()
shared = dh.shared_key(a, B)
print(f"Shared key: {shared}")

conn.close()
listener.close()
