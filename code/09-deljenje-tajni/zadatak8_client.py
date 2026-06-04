# pre pokretanja: python zadatak8_setup.py, pa pokrenuti bar t+1 servera
from kurs.network import ClientConnection
import schnorr
from shamir import g, p, q
from zadatak8_keys import A

m = b"matf kripto"
signers = [1, 3, 5]

# Runda 1: prikupi R_i od svakog potpisnika i izračunaj zajedničko R = prod R_i.
conns = {}
R = 1
for i in signers:
    conn = ClientConnection.connect(port=12344 + i)
    conn.send(signers)
    R = (R * conn.recv()) % p
    conns[i] = conn

# Runda 2: pošalji svima zajednički izazov c i saberi delimične potpise.
c = schnorr.challenge(R, m)
P = 0
for i in signers:
    conns[i].send(c)
    P = (P + conns[i].recv()) % q
    conns[i].close()

print(f"validan potpis: {schnorr.verify(m, R, P, A)}")
