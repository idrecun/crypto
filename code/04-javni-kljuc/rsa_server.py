from kurs.network import Listener
import rsa

d, (n, e) = rsa.generate_keys()

listener = Listener()
listener.start()

conn, _ = listener.accept()

conn.send((n, e))
c = conn.recv()
m = rsa.decrypt(c, d, n)

print(f"Decrypted message: {m}")

conn.close()
listener.close()
