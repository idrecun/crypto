from kurs.network import Listener
import dh

e1, E1 = dh.generate_keys()
e2, E2 = dh.generate_keys()

listener = Listener()
listener.start()

conn1, _ = listener.accept()
conn2, _ = listener.accept()

conn1.send(E1)
conn2.send(E2)

A = conn1.recv()
B = conn2.recv()

shared1 = dh.shared_key(e1, A)
shared2 = dh.shared_key(e2, B)
print(f"Shared key with A: {shared1}")
print(f"Shared key with B: {shared2}")

conn1.close()
conn2.close()
listener.close()
