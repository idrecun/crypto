# Kod za kurs kriptografije

Ovaj repozitorijum sadrzi implementacije i vezbe za kurs kriptografije.

## Struktura repozitorijuma

- `01-protocne-sifre/` - materijali za protocne sifre
- `02-blok-sifre/` - materijali za blok sifre
- `src/kurs/` - zajednicka pomocna biblioteka (`kurs`)

Studenti treba da importuju pomocne funkcije sa top-level nivoa:

```python
from kurs import bytes_to_bits, bits_to_bytes, xor, AES_SBOX
```

## Podesavanje (Linux)

Pokrenuti jednom nakon kloniranja:

```bash
make setup
source .venv/bin/activate
```

Napomena: prvi `make setup` moze da traje 1-2 minuta (ponekad i duze), posebno dok `pip` preuzima metapodatke i pakete. To je ocekivano.

## Nakon povlacenja izmena

Ponovo pokrenuti setup nakon svakog `git pull`:

```bash
make setup
```

Bezbedno je pokretati vise puta i osigurava da se instaliraju sve novododate zavisnosti.

## Korisne komande

```bash
make reinstall   # clean + setup
make clean       # uklanja venv i Python cache fajlove
```
