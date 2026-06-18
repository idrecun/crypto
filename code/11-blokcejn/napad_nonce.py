"""Napad: ponovljen nonce u ECDSA potpisu otkriva privatni ključ.

Ako potpisnik dvaput upotrebi isti slučajan broj k (npr. zbog lošeg generatora),
napadač iz dva potpisa rekonstruiše tajni ključ i potpisuje šta god želi. Isti
napad smo videli u lekciji o eliptičkim krivama — ovde ga primenjujemo na novac
na lancu (ovako je ukradeno više bitkoina sa Android novčanika 2013).

Pokretanje: python napad_nonce.py
"""
import ecdsa
from kurs import ec_n
from params import node_keys

a, A = node_keys(1)["t_priv"], node_keys(1)["t_pub"]   # žrtva = čvor 1

k = 0xC0FFEE                                            # ponovljen nonce
m1, m2 = b"placam Ani 5", b"placam Bobi 7"
(u1, s1) = ecdsa.sign(m1, a, k=k)
(u2, s2) = ecdsa.sign(m2, a, k=k)
print("isti nonce -> ista vrednost u (= R_x) u oba potpisa:", u1 == u2)

# Iz s = k^{-1}(h + a·u):  s1 - s2 = k^{-1}(h1 - h2)  =>  k,  pa  a = (s1·k - h1)/u.
h1, h2 = ecdsa._hash(m1), ecdsa._hash(m2)
k_rec = ((h1 - h2) * pow(s1 - s2, -1, ec_n)) % ec_n
a_rec = ((s1 * k_rec - h1) * pow(u1, -1, ec_n)) % ec_n
print("rekonstruisan nonce tačan: ", k_rec == k)
print("rekonstruisan PRIVATNI KLJUČ tačan:", a_rec == a)

forged_m = b"posalji sav novac napadacu"
forged = ecdsa.sign(forged_m, a_rec)
print("falsifikovan potpis žrtvinim ključem prolazi proveru:",
      ecdsa.verify(forged_m, forged, A))
