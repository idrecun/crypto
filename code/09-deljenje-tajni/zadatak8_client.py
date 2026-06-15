# pre pokretanja: bar t+1 učesnika (python zadatak8_server.py <i> 5 2)
import schnorr
from shamir import p, q
from kurs.network import connect_retry

m = b"matf kripto"
signers = [1, 3, 5]

# Poveži se sa svim potpisnicima; svaki prvo šalje zajednički javni ključ A.
conns = {}
A = None
for i in signers:
    conns[i] = connect_retry(12344 + i)
    A = conns[i].recv()

# Runda 1: pošalji skup potpisnika i prikupi R_i; zajedničko R = prod R_i.
R = 1
for i, conn in conns.items():
    conn.send(signers)
    R = (R * conn.recv()) % p

# Runda 2: pošalji zajednički izazov c i saberi delimične potpise.
c = schnorr.challenge(R, m)
P = 0
for i, conn in conns.items():
    conn.send(c)
    P = (P + conn.recv()) % q
    conn.close()

print(f"validan potpis: {schnorr.verify(m, R, P, A)}", flush=True)
