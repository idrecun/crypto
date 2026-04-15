import lfsr
from secrets import token_bytes

poruka = b"zdravo svete!"
kljuc = b"gg"  # LFSR implementacija je hardkodovana na 16 bitova

sifrat = lfsr.encrypt(kljuc, poruka)
print(f"Sifrat: {sifrat.hex()}")

desifrovana_poruka = lfsr.decrypt(kljuc, sifrat)
print(desifrovana_poruka)

# Ako koristimo IV duzine 8 bitova, dobijamo drugaciji sifrat svaki put
manji_kljuc = b"g"
iv = token_bytes(1)  # IV duzine 8 bitova

sifrat_iv = lfsr.encrypt_iv(manji_kljuc, iv, poruka)
print(f"Sifrat: {sifrat_iv.hex()}, IV: {iv.hex()}")

desifrovana_poruka_iv = lfsr.decrypt_iv(manji_kljuc, iv, sifrat_iv)
print(desifrovana_poruka_iv)
