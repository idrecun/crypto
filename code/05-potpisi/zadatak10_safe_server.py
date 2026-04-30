# pre prvog pokretanja: python zadatak10_setup.py
from kurs.network import Listener
import elgamal
from zadatak10_keys import users

accounts = {"ana": 100, "boban": 50}
seen_nonces = set()

listener = Listener()
listener.start()

while True:
    conn, _ = listener.accept()
    sender, recipient, amount, nonce, R, s = conn.recv()

    if nonce in seen_nonces:
        print("odbijeno (ponavljanje)")
    else:
        tx = f"{sender}->{recipient}:{amount}:{nonce}".encode()
        if not elgamal.verify(tx, R, s, users[sender]):
            print("odbijeno (potpis)")
        elif accounts[sender] < amount:
            print("odbijeno (nedovoljno sredstava)")
        else:
            seen_nonces.add(nonce)
            accounts[sender] -= amount
            accounts[recipient] += amount
            print(accounts)

    conn.close()
