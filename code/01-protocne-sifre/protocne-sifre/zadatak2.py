sifrati = [
    bytes.fromhex("b83f0d799979e6a47f4681d646e7143f"),
    bytes.fromhex("a7290475db7e3e56edd221347d73acbf"),
    bytes.fromhex("b83f0d7f825185169f6daa2bd7c9b9a8"),
    bytes.fromhex("b3351e699864a920a85fda54f346db8d"),
    bytes.fromhex("b83f0d7f825185019662f52865572129"),
]

# Namerno implementiramo xor tako da ne proverava da li su duzine ulaza jednake
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Primetimo da šifrati na pozicijama 0, 2 i 4 počinju sa nekoliko istih
# bajtova. To znači da su u pitanju poruke koje počinju sa istim bajtovima.

print(xor(sifrati[0], sifrati[2])) # b'\x00\x00\x00\x06\x1b(c\xb2\xe0++\xfd\x91.\xad\x97'
print(xor(sifrati[0], sifrati[4])) # b'\x00\x00\x00\x06\x1b(c\xa5\xe9$t\xfe#\xb05\x16'
print(xor(sifrati[2], sifrati[4])) # b'\x00\x00\x00\x00\x00\x00\x00\x17\t\x0f_\x03\xb2\x9e\x98\x81'
print()

# Kako se poruke na pozicijama 2 i 4 poklapaju u prvih 7 bajtova, a pritom se
# sa porukom 0 poklapaju u prva 3 bajta, u pitanju su sigurno poruke LOGIN i LOGOUT
# poruke (nijedan drugi par ne deli prefiks duzine tacno 3). Pretpostavimo da
# je poruka na poziciji 0 LOGIN poruka.

delimican_kljuc = xor(sifrati[0], b"LOGIN|")
print(xor(delimican_kljuc, sifrati[0])) # b'LOGIN|'
print(xor(delimican_kljuc, sifrati[1])) # b'SYNE\x0c{'
print(xor(delimican_kljuc, sifrati[2])) # b'LOGOUT'
print(xor(delimican_kljuc, sifrati[3])) # b'GETYOa'
print(xor(delimican_kljuc, sifrati[4])) # b'LOGOUT'
print()

# Uspesno smo odredili prva 3 bajta poruka na pozicijama 1 i 3, ali ne i vise
# od toga (jer SYNE i GETY nisu validni prefiksi poruka), sto znaci da prava
# poruka na poziciji 0 nije LOGIN (u suprotnom bismo otkrili bar 6 ispravnih
# bajtova).

delimican_kljuc = xor(sifrati[0], b"LOGOUT")
print(xor(delimican_kljuc, sifrati[0])) # b'LOGOUT'
print(xor(delimican_kljuc, sifrati[1])) # b'SYNC\x17S'
print(xor(delimican_kljuc, sifrati[2])) # b'LOGIN|'
print(xor(delimican_kljuc, sifrati[3])) # b'GET_TI'
print(xor(delimican_kljuc, sifrati[4])) # b'LOGIN|'
print()

# Uspesno smo odredili prvih 6 bajtova svih poruka. Na osnovu pocetka poruke na
# poziciji 3, znamo da je u pitanju poruka GET_TIMESTAMP. Ovo nam omogucava da
# odredimo znatno veci deo kljuca, konkretno 13 bajtova.

delimican_kljuc = xor(sifrati[3], b"GET_TIMESTAMP")
print(xor(delimican_kljuc, sifrati[0])) # b'LOGOUT\x02\xc1\x84M\x1a\xcf\xe5'
print(xor(delimican_kljuc, sifrati[1])) # b'SYNC\x17S\xda3\x16\xd9\xba-\xde'
print(xor(delimican_kljuc, sifrati[2])) # b'LOGIN|asdf12t'
print(xor(delimican_kljuc, sifrati[3])) # b'GET_TIMESTAMP'
print(xor(delimican_kljuc, sifrati[4])) # b'LOGIN|admin1\xc6'
print()

# Ovo nam je dovoljno da izvucemo ID-eve korisnika.

desiforvani = [xor(delimican_kljuc, s) for s in sifrati]
print(desiforvani[2][6:12]) # b'asdf12'
print(desiforvani[4][6:12]) # b'admin1'
