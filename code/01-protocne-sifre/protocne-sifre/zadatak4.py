from kurs import xor, bits_to_bytes, bytes_to_bits
import lfsr

sifrat = bytes.fromhex("296a9e72bc5a98f910274dafeff61c5bd3")
deo_sifrata = bytes.fromhex("72bc")
for nibble in range(16):
    deo_poruke = bytes.fromhex(f"6{nibble:x}75")
    deo_streama = xor(deo_poruke, deo_sifrata)

    deo_streama_bits = bytes_to_bits(deo_streama)
    generisano = lfsr.lfsr_reverse(deo_streama_bits, 16 + 4 * 6)
    kljuc_bitovi = generisano[:16]
    kljuc_bajtovi = bits_to_bytes(kljuc_bitovi)
    poruka = lfsr.decrypt(kljuc_bajtovi, sifrat)
    print(poruka)
