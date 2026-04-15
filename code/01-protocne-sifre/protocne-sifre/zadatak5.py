from kurs import xor, bits_to_bytes, bytes_to_bits
import lfsr

sifrat = bytes.fromhex("dfa9dfc3a06c9506b6fcc1ad0d290af6fb92047d")
deo_poruke = bytes.fromhex("d617")
deo_sifrata = bytes.fromhex("06c9")
deo_streama = xor(deo_poruke, deo_sifrata)

deo_streama_bits = bytes_to_bits(deo_streama)
generisano = lfsr.lfsr_reverse(deo_streama_bits, 16 + 4 * 9)
kljuc_bitovi = generisano[:12]
print(kljuc_bitovi)
kljuc_iv_bajtovi = bits_to_bytes(kljuc_bitovi + [0, 1, 1, 1])
poruka = lfsr.decrypt(kljuc_iv_bajtovi, sifrat)
print(poruka)

drugi_kljuc_iv_bajtovi = bits_to_bytes(kljuc_bitovi + [1, 0, 0, 1])
drugi_sifrat = bytes.fromhex("2c3641c356038d362309704493c938221789db47")
druga_poruka = lfsr.decrypt(drugi_kljuc_iv_bajtovi, drugi_sifrat)
print(druga_poruka)
