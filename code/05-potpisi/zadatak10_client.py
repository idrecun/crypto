# pre prvog pokretanja: python zadatak10_setup.py
from kurs.network import ClientConnection
import elgamal
from zadatak10_keys import ana_priv, boban_priv

priv_for = {"ana": ana_priv, "boban": boban_priv}

sender = input("posiljalac: ")
recipient = input("primalac: ")
amount = int(input("iznos: "))

tx = f"{sender}->{recipient}:{amount}".encode()
R, s = elgamal.sign(tx, priv_for[sender])

conn = ClientConnection.connect()
conn.send((sender, recipient, amount, R, s))
conn.close()
