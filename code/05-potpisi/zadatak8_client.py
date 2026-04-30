# pre prvog pokretanja: python zadatak8_setup.py
from kurs.network import ClientConnection
import rsa
from zadatak8_keys import server_pub

n, e = server_pub

conn = ClientConnection.connect()

blob, s = conn.recv()

if rsa.verify(blob, s, e, n):
    with open("received_software.txt", "wb") as f:
        f.write(blob)
    print("potpis validan, softver sacuvan")
else:
    print("potpis nije validan, odbijam softver")

conn.close()
