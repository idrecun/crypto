# Lekcija 11 — Igračka primena: blokčejn sa privatnošću (Monero stil)

Mali blokčejn koji se zaista pokreće kao više čvorova (P2P, dokaz rada, najduži
lanac). Podržava dve vrste transakcija: **transparentne** (Part 1) i **skrivene**
(Part 2, pun RingCT): stealth adrese skrivaju primaoca, MLSAG prstenasti potpis sa
slikom ključa skriva pošiljaoca, a Pedersenove obaveze + dokazi opsega skrivaju
iznos. Jedina crna kutija je dokaz opsega (`kurs.rangeproof`).

## Pokretanje

```
python demo.py                 # 3 čvora na localhost-u: konsenzus + 2 transakcije
python test_mreza.py           # svi testovi (primitive, knjiga, mreža, napadi)
python node.py <i> <n>          # jedan čvor, samo localhost (bezbedno, podrazumevano)
python node.py <i> <n> --lan    --peers peers.txt   # vidljiv na LAN-u (uz potvrdu)
python node.py <i> <n> --public --peers peers.txt   # vidljiv svuda 0.0.0.0 (uz potvrdu)
python napad_*.py               # pojedinačne demonstracije napada
python confidential.py          # samostalan prikaz poverljivih iznosa (bez prstena)
```

## Mapa fajlova

**Iskorišćeno iz ranijih lekcija (gotove primitive):**
`ec.py` (aritmetika krive), `ecdsa.py` (potpis), `pedersen.py` (obaveza + H,
hash-to-point), `merkle.py` (stablo), `kurs.rangeproof` (dokaz opsega — crna kutija).

**Novo (gradi se na času):** `stealth.py` (jednokratne adrese),
`ringsig.py` (MLSAG — višeslojni povezivi prstenasti potpis),
`ringct.py` (poverljivi izlazi: obaveza + dokaz opsega + šifrovan iznos, i bilans).

**Jezgro lanca:** `block.py` (blok + PoW), `transaction.py` (vrste transakcija),
`chain.py` (knjiga + provera), `params.py` (težina, nagrada, portovi, ključevi).

**Ostalo:** `wallet.py` (ključevi, skeniranje, sastavljanje transakcija),
`node.py` (P2P čvor), `demo.py` (orkestrator),
`confidential.py` (samostalan prikaz poverljivih iznosa, bez prstena),
`napad_*.py` (napadi), `skelet/` (skelet za čas — vidi `skelet/README.md`).

## Napadi (`napad_*.py`)

| skripta | slabost |
|---|---|
| `napad_prepis.py` | prepisivanje istorije → trošak ponovljenog PoW-a |
| `napad_falsifikat.py` | trošenje tuđeg izlaza bez potpisa → odbijeno |
| `napad_kovkost.py` | kovkost ECDSA potpisa → dva txid-a za istu uplatu |
| `napad_nonce.py` | ponovljen nonce → otkriva privatni ključ |
| `napad_merkle.py` | dvosmislen Merkle koren (CVE-2012-2459) |
| `napad_dvostruka.py` | dvostruka potrošnja → hvata je slika ključa |
| `napad_iznos.py` | „negativan” iznos kuje novac bez dokaza opsega |

## Pojednostavljenja (igračka!)

- Skrivene transakcije su pun **RingCT**: iznosi su skriveni Pedersenovim
  obavezama i stopljeni sa prstenom kroz **MLSAG**. Jedina crna kutija je dokaz
  opsega (ovde prost dokaz po bitovima umesto Bulletproofs-a); `confidential.py`
  daje istu ideju bez prstena, radi postupnog uvođenja na času.
- Fiksna težina (bez podešavanja), nagrada bez provizija, gossip šalje ceo lanac.
- `kurs.network` koristi pickle preko običnog TCP-a (bez šifrovanja/autentifikacije):
  svako ko dođe do porta može da izvrši kod na mašini. Zato je podrazumevano vezivanje
  na `127.0.0.1`; `--lan`/`--public` traže izričitu potvrdu. Za pravi rad preko mreže
  koristiti SSH tunel ili VPN, a ne `--public` direktno.
