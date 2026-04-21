from kurs.network import ClientConnection
import rsa

conn = ClientConnection.connect()

(n, e) = conn.recv()

m = 123
c = rsa.encrypt(m, e, n)

conn.send(c)
conn.close()
print(f"Encrypted message sent.")
