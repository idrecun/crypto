from kurs.network import ClientConnection
from commitment import commit, verify

print("Klijent je pokrenut. Povezivanje sa serverom...")

conn = ClientConnection.connect()

izbori = ["Papir", "Kamen", "Makaze"]
print("1. Papir")
print("2. Kamen")
print("3. Makaze")
izbor = ""
while izbor not in ["1", "2", "3"]:
    izbor = input("Odaberite opciju (1-3): ")
print("Odabrali ste:", izbori[int(izbor) - 1])

protivnik_c = conn.recv()

c, r = commit(izbor.encode())
conn.send(c)

protivnik_izbor, protivnik_r = conn.recv()
if not verify(protivnik_izbor.encode(), protivnik_c, protivnik_r):
    print("Varalica!")

conn.send((izbor, r))

broj = int(izbor)
protivnik_broj = int(protivnik_izbor)

print("Protivnik je odabrao:", izbori[protivnik_broj - 1])

if izbor == protivnik_izbor:
    print("Nerešeno!")
elif (broj - protivnik_broj) % 3 == 2:
    print("Pobedili ste!")
else:
    print("Izgubili ste!")
