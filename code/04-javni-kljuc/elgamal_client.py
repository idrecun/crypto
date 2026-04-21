from kurs.network import ClientConnection
import elgamal

conn = ClientConnection.connect()

A = conn.recv()

m = 123
c1, c2 = elgamal.encrypt(m, A)

conn.send((c1, c2))
conn.close()
print(f"Encrypted message sent.")
