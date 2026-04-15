from kurs import xor, bits_to_bytes, bytes_to_bits
import lfsr

sifrat = bytes.fromhex("7dda6f65ea2aebf23a88925f66")
deo_poruke = bytes.fromhex("f2c2")
deo_sifrata = bytes.fromhex("a2ae")
deo_streama = xor(deo_poruke, deo_sifrata)

deo_streama_bits = bytes_to_bits(deo_streama)
generisano = lfsr.lfsr_reverse(deo_streama_bits, 16 + 4 * 9)
kljuc_bitovi = generisano[:16]
kljuc_bajtovi = bits_to_bytes(kljuc_bitovi)
poruka = lfsr.decrypt(kljuc_bajtovi, sifrat)
print(poruka)
