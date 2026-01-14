# Blok šifre, operacioni modovi i autentifikacija

## Definicija problema

> Ana i Boban žele da komuniciraju poverljivo putem nebezbednog javnog kanala
> (npr. pomoću javne WiFi mreže). Eva, koja kontroliše kanal, može da
> prisluškuje komunikaciju, ali i da menja sadržaj svake poruke. Na koji način
> Ana i Boban mogu da ostvare poverljivu komunikaciju, a da pritom otkriju
> ukoliko je bilo koja poruka izmenjena?

Blok šifre su osnovne kriptografske primitive nad kojima je izgrađena većina
modernih šifarskih sistema. Osim što nude rešenje za problem poverljive
komunikacije, takođe omogućavaju konstrukciju takozvane autentifikovane
enkripcije.

Formalno, blok šifra je šifra \\((E, D)\\) pri čemu je veličina poruke, odnosno
šifrata, fiksirana na \\(n\\) bitova. Kažemo da je \\(n\\) veličina bloka.
Naglasimo da se, zbog tog uslova, blok šifrom ne mogu direktno šifrovati
proizvoljne poruke. Za fiksirani ključ \\(k\\), funkcija \\(E_k(m) = E(k, m)\\)
je permutacija skupa svih bitovskih niski dužine \\(n\\). Cilj prilikom
dizajniranja blok šifre je da se funkcija \\(E_k\\) ponaša kao pseudoslučajna
permutacija (eng. pseudorandom permutation, PRP) za svaki ključ \\(k\\).

## Konstrukcije blok šifre

Uopšteno, blok šifre se konstruišu iterativnom primenom neke jednostavne
invertibilne transformacije koja zavisi od ključa, pri čemu jednu iteraciju
nazivamo rundom, a tu transformaciju funkcijom runde. Ključ \\(k\\) se
proširuje u niz podključeva \\(k_1, \dots, k_r\\) (po jedan za svaku rundu)
jednostavnim pseudoslučajnim generatorom.

~~~python
def encrypt_block(key: bytes, block: bytes) -> bytes:
  keys = key_expansion(key, rounds)
  for k in keys:
    block = round_function(k, block)
  return block

def decrypt_block(key: bytes, block: bytes) -> bytes:
  keys = key_expansion(key, rounds)
  for k in reversed(keys):
    block = round_inverse(k, block)
  return block
~~~

### Osnovne komponente

Dve osnovne komponente koje se koriste u konstrukciji blok šifri su P-tabela
(P-box) i S-tabela (S-box).

P-tabela, uslovno rečeno, vrši permutaciju pozicija bitova. Preciznije,
preslikava \\(m\\) ulaznih bitova u \\(n\\) izlaznih bitova promenom njihovog
redosleda. P-tabela može da permutuje bitove u slučaju da je \\(m=n\\), ali i
da proširi ako je \\(n>m\\), odnosno kompresuje ako je \\(m>n\\).

~~~text
0 1 1 1 0 1 0 1         0   0   1   0         1 1 1 0 0 1 1 0
│ │ │ │ │ │ │ │         │   │   │   │         │ │ │ │ │ │ │ │
0 1 2 3 4 5 6 7         0   1   2   3         0 1 2 3 4 5 6 7
[    P-box    ]        [    P-box    ]        [    P-box    ]
3 2 7 6 1 0 5 4        0 1 2 3 3 2 1 0         0   2   4   6 
│ │ │ │ │ │ │ │        │ │ │ │ │ │ │ │         │   │   │   │ 
1 1 1 0 1 0 1 0        0 0 1 0 0 1 0 0         1   1   0   1 
~~~

S-tabela je komponenta koja vrši supstituciju, odnosno preslikava \\(m\\)
ulaznih bitova u \\(n\\) izlaznih bitova, najčešće definisane pomoću lookup
tabele. Dobro odabrana S-box funkcija uvodi nelinearnost u šifru, otežavajući
kriptoanalizu i pokušaje napada. Nelinearnost podrazumeva da se izlazni bitovi
ne mogu izraziti kao linearne funkcije ulaznih bitova. Za razliku od S-tabele,
P-tabela je linearna transformacija, jer se svaki izlazni bit \\(y_j\\)
predstavlja trivijalnom formulom \\(y_j = x_i\\) gde je \\(x_i\\) neki ulazni
bit. U nastavku je primer S tabele koja preslikava 4 bita u 3 bita:

~~~text
4 bita -> 3 bita (prvi bit određuje red, preostala tri kolonu)

  │ 0 1 2 3 4 5 6 7
──┼────────────────
0 │ 6 0 1 7 2 4 5 3
1 │ 7 6 5 3 0 1 4 2

S(3)  = 7 jer je 3  = 0.011 odnosno (0, 3)
S(13) = 1 jer je 13 = 1.101 odnosno (1, 5)
~~~

### Fajstelova mreža

Fajstelova mreža je konstrukcija koja omogućava da od proizvoljne funkcije
\\(f(k, b)\\) formiramo blok šifru. Blok se deli na dva dela, \\(b=l \parallel
r\\). U jednoj rundi Fajstelove mreže se blok transformiše po formuli \\(l
\parallel r \to r \parallel l \oplus f(k, r)\\). Primetimo da je ova
transformacija invertibilna, bez obzira na to da li je funkcija \\(f\\)
invertibilna.

![Fajstelova mreža](images/fiestel.png)

~~~python
def round_function(key: bytes, block: bytes) -> bytes:
  n = len(block) // 2
  left, right = block[:n], block[n:]
  return right + xor(left, f(key, right))

def round_inverse(key: bytes, block: bytes) -> bytes:
  n = len(block) // 2
  left, right = block[:n], block[n:]
  return xor(right, f(key, left)) + left
~~~

DES je primer šifre zasnovane na Fajstelovoj konstrukciji. Radi nad
blokovima veličine 64 bita, sa ključem veličine 56 bitova i izvršava se u 16
rundi. Funkcija \\(f\\) je definisana kombinovanjem nekoliko pažljivo odabranih
S-tabela sa jednom P-tabelom.

### SP mreža

SP mreža (eng. Substitution-Permutation network, SPN) je konstrukcija koja se
zasniva na naizmeničnoj primeni S-tabela i P-tabele. Sve operacije moraju biti
invertibilne kako bi dešifrovanje bilo moguće. Preciznije, u svakoj rundi se
ključ runde kombinuje sa blokom pomoću xor operacije, zatim se na segmente
bloka primenjuju S-tabele, nakon čega se primenjuje P-tabela. Naredne funkcije
implementiraju rundu SP mreže i njenu inverznu funkciju. Ukoliko je veličina
S-tabele \\(s\\) bita, funkcija `sbox` deli blok na segmente veličine \\(s\\)
bita i na svaki segment primenjuje S-tabelu.

~~~python
def round_function(key: bytes, block: bytes) -> bytes:
  block = xor(block, key)
  block = sbox(block)
  block = pbox(block)
  return block

def round_inverse(key: bytes, block: bytes) -> bytes:
  block = pbox_inverse(block)
  block = sbox_inverse(block)
  block = xor(block, key)
  return block
~~~

Kako je poslednja primena S-tabele i P-tabele invertibilna, potrebno je
primeniti još jedan xor sa ključem na kraju šifrovanja. To znači da
proširivanje ključa mora da generiše \\(r+1\\) podključeva.

~~~python
def encrypt_block(key: bytes, block: bytes) -> bytes:
  keys = key_expansion(key, rounds)
  for k in keys[0:-1]:
    block = round_function(k, block)
  block = xor(block, keys[-1])
  return block

def decrypt_block(key: bytes, block: bytes) -> bytes:
  keys = key_expansion(key, rounds)
  block = xor(block, keys[-1])
  for k in reversed(keys[0:-1]):
    block = round_inverse(k, block)
  return block
~~~

AES je primer blok šifre zasnovane na SPN konstrukciji. Radi nad blokovima
veličine 128 bita, sa ključevima veličine 128, 192 ili 256 bita i izvršava se u
10, 12 ili 14 rundi, zavisno od veličine ključa. Supstitucija (SubBytes korak)
u AES se radi nad bajtovima. Konstruisana je kao kombinacija multiplikativnog
inverzao u \\(F_{2^8}\\) i afine transformacije. Permutacija u AES se vrši u
dva koraka. Blok se posmatra kao matrica dimenzije 4x4 bajta. Prvo se vrši
ciklično pomeranje redova matrice (ShiftRows korak), nakon čega se svaka kolona
transformiše množenjem sa fiksnom invertibilnom matricom nad \\(F_{2^8}\\)
(MixColumns korak). Iako MixColumns korak nije striktno P-tabela, on ispunjava
ulogu mešanja bitova u bloku linearnom transformacijom i na taj način se može
posmatrati kao uopštenje P-tabele.

## Operacioni modovi

Kako bismo šifrovali poruke proizvoljne dužine koristeći blok šifre, potrebno
je da definišemo operacioni mod šifrovanja.

### ECB

ECB (eng. Electronic Codebook) je najjednostavniji operacioni mod. Poruka se
deli na blokove i svaki blok se šifruje zasebno.

~~~python
def encrypt(key: bytes, message: bytes) -> bytes:
  blocks = split_into_blocks(message)
  ciphertext = bytes()
  for block in blocks:
    ciphertext += encrypt_block(key, block)
  return ciphertext

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
  blocks = split_into_blocks(ciphertext)
  message = bytes()
  for block in blocks:
    message += decrypt_block(key, block)
  return message
~~~


### CBC

### CTR

## Kodovi za autentifikaciju poruka

## Zadaci
