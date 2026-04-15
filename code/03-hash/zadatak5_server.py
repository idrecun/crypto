from kurs.network import Listener
import commitment
import random

predmeti = ["karta", "telefon", "lampa", "sladoled", "auto"]
predmet = random.choice(predmeti)

listener = Listener()
listener.start()

# Faza 0: Povezivanje sa klijentima
print("Server je pokrenut. Čeka se na klijente...")
n = 3
clients = []
for _ in range(n):
    conn, addr = listener.accept()
    conn.send(predmet)
    clients.append((conn, addr))
    print("Klijent {} se povezao.".format(addr))

# Faza 1: Prikupljanje obavezivanja od klijenata
print("Prikupljanje obavezivanja od klijenata...")
obavezivanja = {}
for conn, addr in clients:
    ponuda = conn.recv()
    obavezivanja[addr] = ponuda
    conn.send("Ponuda primljena")
    print("Klijent {} poslao obavezivanje.".format(addr))

# Faza 2: Otkrivanje ponuda
print("Otkrivanje ponuda...")
ponude = {}
for conn, addr in clients:
    ponuda, r = conn.recv()
    if commitment.verify(str(ponuda).encode(), obavezivanja[addr], r):
        ponude[addr] = ponuda
        conn.send("Ponuda prihvaćena")
        print("Klijent {} poslao ponudu: {}".format(addr, ponuda))
    else:
        conn.send("Ponuda odbijena")
        print("Klijent {} poslao nevažeću ponudu.".format(addr))

# Faza 3: Određivanje pobednika
print("Određivanje pobednika...")
pobednik = max(ponude, key=ponude.get)
print("Pobednik je klijent {} sa ponudom {}.".format(pobednik, ponude[pobednik]))
for conn, addr in clients:
    if addr == pobednik:
        conn.send("Pobedili ste!")
    else:
        conn.send("Niste pobedili. Najbolja ponuda je {}".format(ponude[pobednik]))

for conn, addr in clients:
    conn.close()
listener.close()
