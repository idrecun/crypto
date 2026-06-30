# Kriptografija - primer ispita

## Zadatak 1 (8 poena)

Blok šifra je definisana na sledeći način:

```python
pbox_table = [7, 3, 6, 2, 5, 1, 4, 0]
pinv_table = [7, 5, 3, 1, 6, 4, 2, 0]

def pbox(block: bytes) -> bytes:
  return bytes(block[i] for i in pbox_table)

def pinv(block: bytes) -> bytes:
  return bytes(block[i] for i in pinv_table)

def encrypt_block(key: bytes, block: bytes) -> bytes:
  assert len(block) == 8
  assert len(key) == 32
  keys = [key[i:i+8] for i in range(0, 32, 8)]
  for k in keys[0:-1]:
    block = xor(block, k)
    block = pbox(block)
  block = xor(block, keys[-1])
  return block
```

Poznato je da se blok \\(m_0\\) šifruje u \\(c_0\\) nekim ključem \\(k\\).
Odrediti blok koji odgovara šifratu \\(c_1\\) za isti ključ \\(k\\).

```
m0 = 506f7a6472617621
c0 = 217925342f722150
c1 = 216225222a782f4e
```

## Zadatak 2 (8 poena)

Data je implementacija klijenta i servera koji igraju sledeću igru. Svaki
igrač počinje sa 0 energije. U svakom potezu, igrači istovremeno biraju
jednu od narednih akcija:

- **napuni** - uvećava energiju za 1 (do najviše 3)
- **pucaj** - košta 1 energiju
- **brani** - košta 1 energiju, blokira pucanje

Igrač koji puca pobeđuje ukoliko se u istom potezu drugi igrač nije branio.

Izmeniti implementaciju tako da ni klijent ni server ne mogu da varaju,
odnosno da ne mogu da odluče svoju akciju nakon što su videli akciju
protivnika.

## Zadatak 3 (8 poena)

Implementirati protokol koji omogućava serveru da autentifikuje klijenta
upotrebom RSA potpisa. Prilikom povezivanja, server klijentu šalje slučajnu
poruku, klijent potpisuje poruku i server proverava potpis. Ukoliko je potpis
validan, autentifikacija je uspešna.

## Zadatak 4 (9 poena)

Poznato je da se poruka \\(M_1\\) (tačka na eliptičkoj krivoj) šifruje u par
\\((R_1, C_1)\\) ElGamalovom šifrom na eliptičkoj krivoj. Odrediti tačku
\\(M_2\\) koja se šifruje u par \\((R_2, C_2)\\). Javni ključ korišćen za
šifrovanje je \\(A\\).

```
# Parametri krive
ec_p = 340282366762482138434845932244680310783
ec_a = 340282366762482138434845932244680310780
ec_b = 308990863222245658030922601041482374867
ec_n = 340282366762482138443322565580356624661
ec_G = (29408993404948928992877151431649155974, 275621562871047521857442314737465260675)

A  = (118540917207673017565771954248543286429, 283374820069736198339597573383908890803)
M1 = (311807116193896827644739253302305279217, 7855887539980666227955101748628403240)
R1 = (151415010088484704178003320625106134310, 200486398184309034106419046503643081603)
C1 = (257002431054630264858677428581341658692, 30216239897067040892715927900490561145)
R2 = (151415010088484704178003320625106134310, 200486398184309034106419046503643081603)
C2 = (37176490317185231572190409936006749595, 156278783123439977215608545494458627497)
```

## Zadatak 5 (9 poena)

Posmatrajmo problem **3-particije**: Dat je multiskup od \\(3m\\) celih brojeva
i ciljna vrednost \\(T\\). Podeliti brojeve u \\(m\\) trojki tako da je zbir
svake trojke jednak \\(T\\).

Opisati neinteraktivni dokaz sa nula znanja o poznavanju jedne 3-particije za
dati multiskup i dato \\(T\\). Moguće je koristiti dokaz o poznavanju mešanja
bez njegovog obrazloženja.

## Zadatak 6 (8 poena)

Lamportovim potpisom su potpisane poruke `0101`, `1011` i `0110` korišćenjem
istog tajnog ključa. Odgovarajući potpisi su `a4f1 7a00 913c 8450`, `0b84 132d
47ea 8450` i `a4f1 7a00 47ea 6c23`. Odrediti potpis poruke `1000` i
obrazložiti postupak.
