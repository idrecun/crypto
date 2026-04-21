from kurs.network import Listener
import elgamal

a, A = elgamal.generate_keys()

listener = Listener()
listener.start()

conn, _ = listener.accept()

conn.send(A)
c1, c2 = conn.recv()
m = elgamal.decrypt(c1, c2, a)

print(f"Decrypted message: {m}")

conn.close()
listener.close()
