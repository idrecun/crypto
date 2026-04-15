# Python kodovi

## Podešavanje

Nakon kloniranja repozitorijuma (i svakog narednog povlačenja izmena) pokrenuti:

```bash
make setup
```

Napomena: prvi `make setup` moze da traje nekoliko minuta.

Naredna komanda pokreće python virtuelno okruženje, čime se učitavaju sve potrebne biblioteke:

```bash
source .venv/bin/activate
```

## Pomoćna bibilioteka

U `src/kurs` nalazi se biblioteka sa svim pomoćnim funkcijama i konstantama
korišćenim u okviru materijala. Unutar python virtuelnog okruženja moguće je
uvući funkcije iz biblioteke na sledeći način:

```python
from kurs import xor
```
