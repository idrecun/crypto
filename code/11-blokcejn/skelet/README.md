# Skelet — šta se implementira na času

Sve mrežne i pomoćne stvari su date; na času se popunjavaju samo kriptografska
mesta (označena `TODO (vežbe)` i `NotImplementedError`). Kad se sve popuni, kod je
identičan referentnoj implementaciji u nadređenom direktorijumu i `demo.py` prolazi.

## Dato (ne dira se)
`ec.py`, `ecdsa.py`, `pedersen.py`, `merkle.py`, `kurs.rangeproof`, `params.py`,
`wallet.py`, `node.py` (P2P mašinerija), `demo.py`.

## Implementira se (redom)

**Part 1 — transparentni lanac**
1. `block.py`: `valid_pow`, `mine` — dokaz rada.
2. `transaction.py`: `make_transparent` — potpisivanje ulaza.
3. `chain.py`: `State._spend_transparent` — provera potpisa, dvostruke potrošnje, bilansa.

**Part 2 — privatnost (RingCT)**
4. `stealth.py`: `sender_share`, `recipient_share`, `one_time_pub`, `one_time_priv`,
   `is_mine` — jednokratne adrese (skrivaju primaoca).
5. `ringsig.py`: `key_image`, `sign`, `verify` — MLSAG (skriva pošiljaoca + bilans).
6. `ringct.py`: `make_output`, `scan`, `balances` — poverljivi izlazi i homomorfni
   bilans (skrivaju iznos); dokaz opsega je gotov u `kurs.rangeproof`.
7. `transaction.py`: `make_shielded` — MLSAG potpis ulaza.
8. `chain.py`: `State._spend_shielded` — MLSAG, slika ključa, bilans, dokazi opsega.
9. `confidential.py`: `balances`, `make_transfer` — ista ideja iznosa bez prstena
   (samostalan prikaz za postupno uvođenje).

> Napomena: `genesis_block` već ubacuje poverljive izlaze (poziva `ringct.make_output`).
> Dok se ne stigne do Part 2, može se privremeno zakomentarisati petlja sa poverljivim
> premine izlazima u `chain.genesis_block`, pa raditi čisto transparentan lanac.
