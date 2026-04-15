from kurs.network import ClientConnection
from commitment import commit

conn = ClientConnection.connect()
predmet = conn.recv()  # Primanje predmeta od servera
print("Predmet za licitaciju:", predmet)

ponuda = int(input("Unesite vašu ponudu: "))
c, r = commit(str(ponuda).encode())  # Obavezivanje ponude
conn.send(c)  # Slanje obavezivanja serveru
print("Server:", conn.recv())  # Primanje potvrde o primanju ponude

conn.send((ponuda, r))  # Slanje ponude serveru
print("Server:", conn.recv())  # Primanje potvrde o prihvatanju ponude
print("Server:", conn.recv())  # Primanje rezultata licitacije

conn.close()

