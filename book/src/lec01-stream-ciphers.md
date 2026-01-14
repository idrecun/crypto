# Klasične i protočne šifre

## Definicija problema

> Ana i Boban žele da komuniciraju poverljivo putem javnog kanala (npr. pomoću
> interneta). Eva, koja prisluškuje komunikaciju, ne sme da sazna sadržaj
> poruka koje Ana i Boban razmenjuju. Na koji način Ana i Boban mogu da ostvare
> poverljivu komunikaciju?

Rešenje ovog problema svodi se na korišćenje šifri. Ana i Boban se mogu unapred
dogovoriti o šifri i ključu koji će koristiti. Pod ključem podrazumevamo neki
tajni podatak koji je poznat samo Ani i Bobanu, a pod šifrom podrazumevamo
algoritam koji proizvoljnu poruku uz dati ključ transformiše u nisku koju
nije moguće protumačiti i razlikovati od slučajne niske. Takvu nisku nazivamo
šifrovana poruka ili šifrat.

Formalnije, šifra je par algoritama \\((E, D)\\), gde je \\(E\\) algoritam
šifrovanja odnosno enkripcije, a \\(D\\) algoritam dešifrovanja odnosno
dekripcije. Algoritam \\(E\\) kao argumente prima poruku \\(m\\) i ključ
\\(k\\) i vraća šifrat \\(c = E(k, m)\\). Algoritam \\(D\\) kao argumente prima
šifrat \\(c\\) i ključ \\(k\\) i vraća poruku \\(m = D(k, c)\\). Šifra je takva
da za svaku poruku \\(m\\) i ključ \\(k\\) važi \\(D(k, E(k, m)) = m\\).

## Klasične šifre

Sada ćemo predstaviti nekoliko klasičnih šifri koje su se istoriјski koristile
za ostvarivanje poverljive komunikaciјe.

### Cezarova šifra

Cezarova šifra je jedna od najjednostavnijih šifri. Enkripcija se vrši
pomeranjem celog alfabeta za fiksan broj mesta \\(k\\). Na primer, za \\(k = 3\\),
alfabet izgleda ovako:

| A | B | C | D | E | F | G | H | I | J | K | L | M |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D | E | F | G | H | I | J | K | L | M | N | O | P |

| N | O | P | Q | R | S | T | U | V | W | X | Y | Z |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Q | R | S | T | U | V | W | X | Y | Z | A | B | C |

Poruka \\(m\\) se onda šifruje tako što se svako slovo u poruci menja
odgovarajućim slovom iz pomerenog alfabeta. Na primer, poruka `HELLO` se
šifruje kao `KHOOR`. Dešifrovanje se, jasno, vrši inverznim mapiranjem
karaktera.

Cezarova šifra je jednostavna, ali je veoma nebezbedna. Postoji samo 25 mogućih
ključeva (pomeraja), pa je moguće probati sve mogućnosti i pronaći pravi ključ.
Na primer, ako je data šifrovana poruka `ZRUOG`, možemo probati sve pomeraje
\\(k\\) redom i dešifrovati šifrovanu poruku dok ne dobijemo smislen rezultat:

~~~text
k=1  YQTNF
k=2  XPSME
k=3  WORLD
~~~

Ovaj postupak je moguće automatizovati statističkom analizom dobijenog teksta u
slučaju dužih poruka. Preciznije, možemo izračunati učestalost pojavljivanja
svakog slova u dobijenom tekstu. Svaki jezik ima karakterističnu raspodelu
učestalosti slova, pa možemo uporediti dobijenu raspodelu sa poznatom
raspodelom za ciljani jezik i izabrati onaj pomeraj koji daje najpribližniju
raspodelu. Na slici je prikazana učestalost pojavljivanja slova u engleskom
jeziku.

![Učestalost slova u engleskom jeziku](images/english.png)

Naredna funkcija implementira jedan od načina za izračunavanje udaljenosti
raspodele učestalosti u poruci u odnosu na poznatu raspodelu za engleski jezik.

~~~python
def analyze(message, freq_eng):
  frequencies = {letter: 0.0 for letter in ascii_lowercase}
  for letter in message:
    if letter.islower():
      frequencies[letter] += 1 / len(message)

  score = 0
  for letter in ascii_lowercase:
    score += abs(frequencies[letter] - freq_eng[letter]) / 26
  return score
~~~

Nju možemo iskoristiti da pronađemo pravi pomeraj u Cezarovoj šifri, pokušavajući
svaki mogući pomeraj:

~~~python
for key in ascii_lowercase:
  message = "".join(dec(c, key) for c in ciphertext)
  score = analyze(message, freq_eng)
  if score < 0.01:
    print(f"Possible decryption for key {key} with score {score}")
    print(f"{message}")
~~~

### Vižnerova šifra

Vižnerova šifra je unapređenje nad Cezarovom šifrom koje koristi ključ u vidu
reči umesto fiksnog pomeraja. Svako slovo ključa određuje jednu vrednost
pomeraja Cezarove šifre (na osnovu svoje pozicije u alfabetu), a svako slovo
poruke se šifruje Cezarovom šifrom na odgovarajućoj poziciji. Na primer, ako je
ključ `SECRET`, odgovarajući pomeraji su dati u sledećoj tabeli:

|  S |  E |  C |  R |  E |  T |
|----|----|----|----|----|----|
| 17 |  4 |  2 | 16 |  4 | 18 |

Onda se poruka `HELLO` šifruje tako što se `H` šifruje Cezarovom šifrom sa
pomerajem 17, `E` šifruje Cezarovom šifrom sa pomerajem 4, itd. Rezultat
šifrovanja je `ZINCS`. U slučaju da je poruka duža od ključa, možemo zamisliti
da se ključ ponavlja dovoljan broj puta da pokrije celu poruku.

Vižnerova šifra je znatno bezbednija od Cezarove šifre, ali i dalje postoje
efikasni napadi na nju. Na primer, možemo pokušati takozvani napad rečnikom.
Ako je ključ kratak i poznatog je oblika (npr. jedna reč engleskog jezika, ili
neka reč sa spiska korišćenih i otkrivenić ključeva), možemo pokušati da
dešifrujemo poruku svim rečima iz rečnika. Zbog ovoga je najbolje koristiti
nasumične, dugačke ključeve i ne upotrebljavati isti ključ više puta.

~~~python
with open("dictionary.txt", "r") as file:
  for word in file:
    key = word.strip()
    message = "".join(dec(c, key[i % len(key)]) for i, c in enumerate(ciphertext))
    score = analyze(message, freq_eng)
    if score < 0.01:
      print(f"Possible decryption for key {key} with score {score}")
      print(f"{message}")
~~~

Postoje i sofisticiraniji napadi na Vižnerovu šifru. Na primer, ako je dužina
ključa \\(n\\) poznata, možemo podeliti šifrovanu poruku u \\(n\\) grupa, gde
svaka grupa sadrži karaktere koji su šifrovani pomoću istog pomeraja. Na
primer, ako pretpostavljamo da je dužina ključa 3, onda delimo poruku
`HELLOWORLD` u grupe `H..L..O..D`, `.E..O..R..` i `..L..W..L.`. Za svaku grupu
onda možemo primeniti analizu učestalosti slova kao u Cezarovoj šifri da bismo
otkrili odgovarajući pomeraj.

~~~python
subtexts = [ciphertext[i::length] for i in range(length)]
key_candidates = [get_caesar_keys(subtext, freq_eng) for subtext in subtexts]

for key in ["".join(prod) for prod in product(*key_candidates)]:
  message = "".join(dec(c, key[i % len(key)]) for i, c in enumerate(ciphertext))
  score = analyze(message, freq_eng)
  if score < 0.01:
    print(f"Possible decryption for key {key} with score {score}")
    print(f"{message}")
~~~

Možemo pokušati sve moguće dužine ključeva redom dok ne pronađemo smislen
rezultat. Ipak, dužinu ključa možemo pokušati i da procenimo pametnije.
Primetimo da ako u šifrovanoj poruci postoji segment koji se ponavlja, moguće
je da je u pitanju ista reč teksta koja je šifrovana istim delom ključa. Ako je
tako, to znači da je razmak između ta dva ponavljanja deljiv sa dužinom ključa.
Naravno, ne mora svako ponavljanje značiti da se ovaj scenario desio (ovo
postaje očigledno ako gledamo segmente dužine jedan karakter), ali što je duži
taj ponovljeni segment, to je verovatnije da se radi o takvom poklapanju.
Možemo odabrati dužinu \\(L\\) i pronaći sve ponovljene segmente dužine \\(L\\)
u šifrovanoj poruci. \\(L\\) biramo tako da bude dovoljno veliko da izbegnemo
previše slučajnih ponavljanja, ali i dovoljno malo kako bismo uhvatili dovoljan
broj ponavljanja. Dužina ključa je onda verovatno delilac nekog od razmaka
između pronađenih ponavljanja. Radi ubrzanja postupka možemo preskočiti sve
delioce koji se ne pojavljuju više od jednom. Ovaj postupak je poznat kao napad
Kasiskog. U nastavku je njegova implementacija.

~~~python
L = 5
gaps = []
for i in range(len(ciphertext) - L + 1):
  substring = ciphertext[i : i + L]
  gaps.extend(
    match.start() - i for match in re.finditer(substring, ciphertext[i + 1 :])
  )

divisors = {}
for gap in gaps:
  for d in get_divisors(gap):
    if d in divisors:
      divisors[d] += 1
    else:
      divisors[d] = 1

candidates = set()
for d in divisors:
  if divisors[d] > 1:
    candidates.add(d)
~~~

Nakon određivanja mogućih dužina ključeva, možemo pokušati da otkrijemo poruku
svakom od njih, prethodno opisanim postupkom.

### Jednokratna šifra (One-time pad)

Jednokratna šifra je šifra koja je teoretski neprobojna ako se koristi na
pravilan način. Ključ je slučajan niz bitova koji je jednako dug kao i poruka.
Enkripcija se vrši tako što se poruka kombinuje sa ključem pomoću operacije
XOR, odnosno \\(E(k,m) = k \oplus m\\). Jasno, dekripcija se vrši na isti
način, tj. \\(D(k, c) = k \oplus c\\).

Kako bi šifra zaista bila neprobojna, ključ mora biti slučajno generisan, iste
dužine kao i poruka, korišćen samo jednom i čuvan u tajnosti. Ako bar jedan od
ovih uslova nije ispunjen, šifra postaje podložna napadima.

Primera radi, recimo da smo poslali dve poruke \\(m_{1}\\) i \\(m_{2}\\)
enkriptovane istim ključem \\(k\\). Neka su šifrati \\(c_{1} = E(k, m_{1})\\) i
\\(c_{2} = E(k, m_{2})\\). Tada je \\(c_{1} \oplus c_{2} = (k \oplus m_{1})
\oplus (k \oplus m_{2}) = m_{1} \oplus m_{2}\\). Kako bismo najbolje prikazali
koliko je ovo katastrofalno, posmatrajmo šta se dobije ako su \\(m_{1}\\) i
\\(m_{2}\\) dve slike iste veličine:

![OTP](images/otp.png)

Iako su slike pomešane XOR operacijom, moguće je tačno razaznati šta se nalazi
na kojoj slici (lav na jednoj, put u pustinji na drugoj).

Jasno je da ove uslove nije lako ispuniti u praksi. Jedan od pokušaja da se
napravi praktična jednokratna šifra je korišćenje generatora slučajnih
bitova. Ukoliko je generator dovoljno dobar, moguće je generisati dugačke
nizove bitova koji izgledaju nasumično i koristiti ih kao ključeve za OTP.

## Protočne šifre

Protočne šifre zasnivaju se na generisanju pseudoslučajnog niza bitova na
osnovu datog ključa, koji se na neki način kombinuje sa porukom, uglavnom XOR
operacijom. Preciznije, neka je \\(G\\) pseudoslučajni generator (eng.
pseudorandom generator, PRG) koji na osnovu ključa \\(k\\) generiše niz bitova
\\(b_{1}, b_{2}, \dots\\). Tada možemo definisati protočnu šifru kao par
algoritama \\((E, D)\\) gde je \\(E(k, m) = G(k) \oplus m\\) i \\(D(k, c) =
G(k) \oplus c\\). Primetimo da je ovo suštinski jednokratna šifra, pri čemu
sada ključ može biti kraći od poruke. Naglasimo da ovim još uvek nismo rešili
problem ponovnog korišćenja ključa.

Obradićemo konstrukciju protočne šifre zasnovane na linearnim povratnim šift
registrima. Ovakve protočne šifre su istoriјski bile veoma značajne, ali se
danas ne koriste u kriptografske svrhe zbog svojih slabosti.

### LFSR

Linearni povratni šift registar (eng. linear feedback shift register) drži
stanje od \\(n\\) bitova \\(s_{1}, \dots, s_{n}\\). Svaki naredni bit
pseudoslučajnog stanja računa se po formuli \\(s_{i} = c_{n} s_{i - n} \oplus
\dots \oplus c_{1} s_{i-1}\\) gde su \\(c_{1}, \dots, c_{n}\\) bitovi koji
definišu registar i služe da odaberu bitove trenutnog stanja na osnovu kojih se
računa naredni bit stanja. Za LFSR je usko vezan polinom \\(C(x) = c_{n} x^n +
\dots + c_{1} x + 1\\) sa koeficijentima u \\(\mathbb{F}_{2}\\).

Na primer, neka je LFSR dužine \\(n=4\\) definisan polinomom \\(x^4+x^3+x+1\\).
To znači da se naredni bit stanja računa po formuli \\(s_i = s_{i-4} \oplus
s_{i-3} \oplus s_{i-1}\\).

~~~text
 ┌──>s[i-1] s[i-2] s[i-3] s[i-4]───> output
 │     │             │      │
 └───[          XOR          ]
~~~

Ako je početno stanje \\(s_{i-1}, s_{i-2}, s_{i-3}, s_{i-4} = 1, 0, 0, 0\\),
prvih nekoliko koraka pomeranja registra izgleda ovako:

~~~text
 1 0 0 0       1 1 0 0       1 1 1 0       0 1 1 1       0 0 1 1    
 |   | |       |   | |       |   | |       |   | |       |   | |    
 +---+-+-> 1   +---+-+-> 1   +---+-+-> 0   +---+-+-> 0   +---+-+-> 0
~~~

Naredna funkcija implementira LFSR generator sa početnim stanjem `state`.
Generiše se `b` bitova pseudoslučajnog niza.

~~~python
def lfsr(state: list[int], b: int) -> list[int]:
  stream = state + [0] * b
  for i in range(len(state), len(stream)):
    stream[i] = stream[i - 1] ^ stream[i - 3] ^ stream[i - 4]
  return stream[len(state):]
~~~

Implementaciju možemo uopštiti i da prihvata proizvoljni LFSR polinom u vidu
liste pozicija koeficijenata čija je vrednost 1.

~~~python
def lfsr(state: list[int], taps: list[int], b: int) -> list[int]:
  stream = state + [0] * b
  for i in range(len(state), len(stream)):
    for t in taps:
      stream[i] ^= stream[i - t]
  return stream[len(state):]
~~~

Od LFSR generatora možemo napraviti protočnu šifru tako što ključ koristimo kao
početno stanje registra, a zatim generišemo niz bitova koji se kombinuju sa
porukom pomoću XOR operacije. Veličina ključa mora da odgovara veličini
registra.

~~~python
def encrypt(key: bytes, message: bytes) -> bytes:
  keystream = lfsr(bytes_to_bits(key), 8 * len(message))
  return xor(bits_to_bytes(keystream), message)

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
  keystream = lfsr(bytes_to_bits(key), 8 * len(ciphertext))
  return xor(bits_to_bytes(keystream), ciphertext)
~~~

Kako bismo rešili problem ponovnog korišćenja ključa, moramo osigurati da LFSR
ne koristi isto početno stanje za različite poruke. Jedan od načina da se to
izbegne je korišćenjem inicijalizacionog vektora (IV). Inicializacioni vektor
je slučajni niz bitova koji se koristi zajedno sa ključem da bi se generisalo
početno stanje LFSR. Na primer, početno stanje registra se može inicijalizovati
kao konkatenacija ključa i inicijalizacionog vektora. Inicializacioni vektor se
šalje zajedno sa šifratom kao javno dostupan podatak, kako bi primalac mogao da
rekonstruiše početno stanje LFSR i dešifruje poruku. Ovo ne umanjuje bezbednost
šifre, već samo osigurava da se za različite poruke koristi različito početno
stanje LFSR.

Naredne funkcije implementiraju enkripciju i dekripciju pomoću LFSR sa
inicializacionim vektorom. Veličina registra treba da bude jednaka zbiru
veličine ključa i veličine inicijalizacionog vektora.

~~~python
def encrypt(key: bytes, message: bytes, iv: bytes) -> bytes:
  keystream = lfsr(bytes_to_bits(key+iv), 8 * len(message))
  return xor(bits_to_bytes(keystream), message)

def decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
  keystream = lfsr(bytes_to_bits(key+iv), 8 * len(ciphertext))
  return xor(bits_to_bytes(keystream), ciphertext)
~~~

Primetimo da ukoliko znamo \\(n\\) uzastopnih bitova generisanih LFSR
generatorom dužine \\(n\\), možemo lako odrediti sve bitove generatora (pošto
su pozicije registra fiksirani, javni podaci). Sve naredne bitove možemo
izračunati direktno primenom generatora. Prethodne bitove možemo izračunati
obrtanjem relacije. Na primer, ako se naredni bit računa kao \\(s_i = s_{i-1}
\oplus s_{i-3} \oplus s_{i-4}\\), onda važi \\(s_{i-4} = s_i \oplus s_{i-1}
\oplus s_{i-3}\\), odnosno \\(s_{j} = s_{j+4} \oplus s_{j+3} \oplus s_{j+1}\\)
uvođenjem smene \\(j=i-4\\). Naredna funkcija implementira određivanje
prethodnih \\(b\\) bitova LFSR generatora na osnovu datih \\(n\\) bitova
stanja.

~~~python
def lfsr_reverse(state: list[int], b: int) -> list[int]:
  stream = [0] * b + state
  for j in range(b - 1, -1, -1):
    stream[j] = stream[j + 4] ^ stream[j + 3] ^ stream[j + 1]
  return stream[:b]
~~~

### NLFSR

Jedan od načina da ojačamo LFSR generator je nelinearnim kombinovanjem više
LFSR generatora u takozvani NLFSR (nelinearni povratni šift registar)
generator. Prikazaćemo par primera NLFSR generatora.

#### Umanjujući generator

Umanjujući generator koristi dva LFSR. U svakom koraku pomeramo oba generatora
za jedan korak. Ukoliko prvi generator vrati 1, na izlaz NLFSR generatora
ispisujemo bit drugog generatora. Ako prvi generator vrati 0, bit drugog
generatora se preskače.

~~~text
 [LFSR A]───────┐
 [LFSR B]──[if A = 1]──> output

Primer:
 A: 0110101110
 B: 1010011100
 O:  01 0 110
~~~

#### Naizmenični generator

Naizmenični generator je NLFSR koji koristi tri LFSR generatora. Kontrolni
generator se pomera u svakom koraku. U zavisnosti od toga da li je generisao 0
ili 1 bira se koji od druga dva LFSR generatora se pomera. Na izlaz NLFSR se
ispisuje XOR izlaznih bitova drugog i trećeg LFSR (u XOR se koristi poslednji
generisan bit generatora koji nije pomeren).

~~~text
 [LFSR C]─┬─[LFSR A, clock if C = 0]─[XOR]─> output
          └─[LFSR B, clock if C = 1]───┘

Primer:
 C:  01100011
 A: 01..011..
 B: 1.01...01
 O:  01010010
~~~

## Zadaci

### Zadatak 1

Data je implementacija protočne šifre zasnovane na pseudoslučajnom generatoru
\\(G\\). Objasniti slabost ove implementacije i ispraviti je.

~~~python
def encrypt(key: bytes, message: bytes) -> bytes:
  generator = G(key)
  keystream = generator.generate(len(message))
  return xor(keystream, message)

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
  generator = G(key)
  keystream = generator.generate(len(ciphertext))
  return xor(keystream, ciphertext)
~~~

### Zadatak 2

Klijent i server komuniciraju koristeći ključ \\(k\\) i šifru iz Zadatka 1.
Poruke koje razmenjuju definisane su nekim protokolom. Svaka poruka se
dopunjava slučajnim bajtovima do 16 bajtova pre šifrovanja. Spisak validnih
poruka je sledeći:

~~~text
LOGIN|<id>
LOGOUT
PING
SYNC
GET_STATUS
GET_TIMESTAMP
~~~

Poznate su šifrovane poruke:

~~~hex
b83f0d799979e6a47f4681d646e7143f
a7290475db7e3e56edd221347d73acbf
b83f0d7f825185169f6daa2bd7c9b9a8
b3351e699864a920a85fda54f346db8d
b83f0d7f825185019662f52865572129
~~~

Odrediti ID svih korisnika iz LOGIN poruka, ako je poznato da je dužina ID-a 6
bajta.

### Zadatak 3

Dat je šifrat `7dda6f65ea2aebf23a88925f66` dobijen šifrovanjem poruke pomoću
LFSR kom odgovara polinom \\(x^{16}+x^{15}+x^{13}+x^4+1\\). Poznat je deo
poruke `.........f2c2.............`. Odrediti celu poruku.

### Zadatak 4

Dat je šifrat `296a9e72bc5a98f910274dafeff61c5bd3` dobijen šifrovanjem poruke
pomoću LFSR kom odgovara polinom \\(x^{16}+x^{15}+x^{13}+x^4+1\\). Poznat je
deo poruke `......6.77.......................`. Odrediti celu poruku.

### Zadatak 5

Dat je šifrat `dfa9dfc3a06c9506b6fcc1ad0d290af6fb92047d` dobijen šifrovanjem
poruke pomoću LFSR kom odgovara polinom \\(x^{16}+x^{15}+x^{13}+x^4+1\\), sa
četvorobitnim inicijalnim vektorom `7`. Poznat je deo poruke
`.........d617...........................`. Odrediti dvanaestobitni ključ i
dešifrovati `2c3641c356038d362309704493c938221789db47` sa inicializacionim
vektorom `9`.

### Zadatak 6

Poruka se šifruje pomoću protočne šifre zasnovane na LFSR kom odgovara polinom
\\(x^{32}+1\\). Odrediti celu poruku. Pretpostaviti da je poruka tekst na
engleskom jeziku.

~~~hex
190f53071804531b15000107500e155304091653121400071c081d145002
1a07094d53041804011650151b1650131b0a04091e531f07531f19071653
12041207034101161c041d071c0400001c185f53040916011541160b1912
07005000530205001a1d04411f1a04151f1650031c1c1b12071c0204531d
110c16175043041b190c001a13001f5300001416034f51531e0400071c04
17531204070415041d53040e041602081d145012180a0302011200040100
5c41071b191253101800011e190f1453180005161e410701110f00031f13
07005008070050171a0019151c010341071c500053041f131f17500e1553
1c0807160200010a50041d1018001d071d041d075e41071b1541001b150d
0516034d531f190f161750161a071841111c1f0a00531f0753121c0d5300
180003160341121d1441001a0a04005f50161b1a031116015015121f1512
531c1641121706041d070513165f50131c1e110f10165c41121d14411e0a
03151601094f530718045312020e1e12500e155311061617501112031513
53121e055307180453001f070753131316121b081d14500e1553070e1c17
150f53151c0e1c01120e12011412531002041207154112531e0e0007110d
141a1341121e1208121d1304530718000753150c11011102160050040516
0218530519121a071f135d530409165300131c03020816071f135f53110f
53161302161d04131a1050031a111c081c0318081f1650161a0718411253
00041d1018001d0750071c015012071c021807161c0d1a1d174d53140204
16070341100603151c1e151300530708071b5000530411131e53030c1a1f
1541121d1441125317041d06190f165300000000190e1d53160e01530409
165307131a0704041d53070e01175e41120050111207020e1d00500c1612
1e05160150151b011f14141b50151b1650001a001c04005f50151b160941
1e1209410007050c111f154106031f0f531b190517161e41121f130e0516
034112171f131d161441041a04095305190f07121704531f1500071b1513
5e111f141d1750021f1203121a1003411c0150021c090941011611051a1d
17411d1c1f0a0053070916011541071a1d04530015041e0050151c530315
121d14410007190d1f5d50081d5304091a00500c12141902121f50120312
13045f5304091653120e061d1400011a1512531115150416150f53011500
1f1a041853121e0553151902071a1f0f53111c14015f50001d1750040516
021853111f0e18531204101c1d0400531141031c0215121f50151c531141
171a16071601150f07530204121f1d4d531a1e171a07190f145302041217
15130053040e53161d0312011b411c1d500d1a07151312010941191c0513
1d1609125307180007530413121d0302161d1441071b1541101c1e071a1d
1512531c1641071b1541160515130a1711185d5307091a1e030810121c41
0312170400530315121d141253120341125304040007110c161d0441071c
50151b1650041d1705131a1d1741031c070401531f07531f191516011115
06011541071c501501121e12031c02155f53190f00031913165f50001d17
50021c1d1e04100750140053040e53071804530511120753040003160315
010a500e155318141e121e411a1e11061a1d11151a1c1e4f
~~~

### Zadatak 7

Slika se šifruje pomoću protočne šifre zasnovane na LFSR kom odgovara polinom
\\(x^{16}+x^{15}+x^{13}+x^4+1\\). Odrediti sadržaj slike.

~~~hex
01b09d5188d8926f83b90997b0aeebb28750b8dbb589ec341dc699d8ea7d
fc7d32534cadda6a307cb7e83a1495dd7d2079f8a5a4db0a631b5c65f50a
d6c8ab1aa92061c59a16ae74983d2abe643555c04566db6f1d512e2a7df5
874a8af5e45a41617ef0f62471223a335caff1adfdcf4adde17535a3474d
a88159916bcafe4b76f790635b735bf189b3acdc34c2aefe30e1794c6916
494bd0765ba614be5c203ccfe8e7ff83d3d5ace765777d9f7eb0308a83ab
1c0efc58fb444409e6fca092dd131b3f09c509912fc53f2d1bb77e74cafb
e3259ae68ee566190ea1f725aacabda90862be6b987b94188d5e6cb9b594
b992d83534699e573209a020dd4f8e9ce85d8afa706a1258db5203538abc
72f138ffb0c0a231657fb2d9903d783dc36c5dd84e2a4efe1525774b3f60
73cf66f129327140713177f9c3c78e7892f15223f3b70ad02833cfbe241f
872bbb3b318b6adff1fd3a890ff404286c4e0b2066a29f951d0a5d525f63
9aa76dae5815cdace0be2618ec1145a3b53bb36576ed0d8692c5ad5e3d51
85a9d8b36439992d3d6933401b46898a0fa339f94704530b33bd88bf157e
727f82612aa10aa6dcf5a7f1a9167582fec611e28468726c5edbfd266247
dc2518bc4c8e355c003916f6b1686e399cef14f0776393ddabbabc3310fe
8cf658e8890c8ff5d1535f57a501f3769b885d97c20c9b2ffe5a640828d8
39765081a2e23ff62a4ef101a2ec6a1500ad0fe614326a36666e68cad316
779bf5baf18c0bfc74ef7bf52e9d2b60b4852f3f1332bf38276e8c357a38
ee6dda701f4ffe0afb940aaf6b1cbe20abfc0708a064c853fa0938303f16
6961f3fab88ab835b4c367b12a10d4dce31f74e895bd52a2c9f8f294d40f
7dc4789b8b4da5ecaedcc85c3817696270df41810126829d3ad46f2379bb
a441b1b68fe65282fbdc2d190a26ff80bdccbf68d0c42a54fda13e569f06
2b2fda374e4a6e84007916574e75a35a6b63aa440b2b70f60c7798b338dc
91aa5e7296a216ba255ca893ffaf8aa7fcc41452d6756a13938881e68e5a
cc2875ea476e54cdd499bc21e36a058dce7505bf55a91009d1d09cdd69ae
c086214745437c781cfc7853c4cc93d2ff62121d7a6a3627cc9b16f22966
46f2254290a9e98587acde606d9720b85b326fe2c4c3719e873735a97051
153a9148dc59384a56819ff08c10756761ed9b1ee3a2e26dcfddce9b1697
2716571960a665e7603d747ed0fb7edca865122b5b4f042971eef5355801
14696197cafb3c691a29b5dabc94fefbc76300aff88b27c2543a94dccb47
aaf1eb88b7407c985088ec2c6349887ea707ffea1afcf33e8cfa80a84ca3
998f101fcab6c54dc31d3ff170eb9b1bb24436e50c190698abd0bab17be1
3a0f90007efce93b7cad3e2da43af4ec091ba5358d83ffb3f21f42949b7a
8d01b9442db6399e1c15f9af72faa21c00f57885d12eb6e2d3ebd3dece84
2887a3ce73cf8508b999e826ffd5add2b34ea4ccbd54ecca83a4aa5102b1
83ed5e1bfcd88762ca302eec822d7493fae27bb7c09328e420265dd8f887
fbe2bc35c2e0885c8ff1c1e35435162875ccbe54c8426dba87fd08721eab
1615806f8a27fecc6cc3518ef03771bb08054b8a81a3cc7b261370efc0c7
84400d558a0d012b2d37170c0fd42e8b920e6b1a7d34f47c8db697dce392
45277af8dbc23de7461f785846e9790d011fd0fd6df708e3de030b5e8298
cb4e4d2d6ae98e67384408c78a15128392744caf61286a05e2e64a169618
7a171de3e09f2bd66090ae26f38d798b4ea490ed35d56e9dd0b0ae1b7e6c
ea672d30889eff5f1c28e3a6abb803b892e79db0ffe7b347a681c7eaaae2
0caeb7f371a61dfea0ae3380a1b18d08a81acb77a69a3c44a46dbfa0d103
ec490d57ff7fcb4cb2fb22edf04a921eb0c41b996f018c4c6ca1f325774b
7c869ca7f0620c190870ead47c49e4ecfd7380db0803ea01c3b94e57c217
cc4b5476c210b6c19473bd534ee2d03b8cc3d3a7c0af166f5842c38b87ea
d8020262194b01c827583aab043e97c73d1b894bc6c943dbc320b0f32afa
7bbf7c7b13ce38204bf6f3eadd12a18db7b19890db7527c31006b8c551df
8c495a8ac948b1d79dbbeae09e69edf1607e3af100b3a27eb280bef9de3c
52b23703953b4a01b552d7e5f7dbc51bbfca901d2608ceaa859842b1b702
c75cf697040961f1638693f4297db6a9a74c8dd337ee62dfb63f820ec260
7a93a147fc087e7d429153ae2c3f1592a4d87cf05cc7a563b69cd987c044
3e0f138836f2c6468b8a94a429c2c5d1abc4ddc97d6a691feb06edd38788
51419c7921d514949cc425ac2677ced325dd82b5fb64ab7f3d1b25ffa72f
9297949e923ceab007a4214d2a41ed8c44e5778b3b94d5ff6b7ea918398c
087dcdbc2256cd1849e80bb2fb8516fd04df17faa4ad1d42ffb30b0a9e11
48a90ceb586fa39aea408f81a44ab656eebe179ab4a260376c149656c79a
5720ba5a16c3f4237faa0c3c43db46d75cbc29b4cc927df3a4ae864477c7
a0bbf40803e7866b96c605dc281a3191c9546e5cd15da68f1595e9a1defe
c28590076385e513b4b44c8648e2e7213e21be1bb45e480c5a9649463224
341a9d360d744461247552dfd7bccb1c97995d84e4334c19baae63f28a73
9431907950709301aa6b0a4ea3613eb5c295e4be80522d1394ded1e2c625
2fa997208f955b56565ef4a153ef23bf01b7ae5fcfe2aa23232b7f29499f
5e7cb2634586fd780c87e22ac89fb62b86d44ebecc9aba1d3382fda998eb
1b454b4b4d8fcf412678a136eb8fc80076d494cdc120338682c4c6050331
721904a6600490db5500c4b37b51e944946c0e203134124df713cc7d8b31
c5913a982039f089e26e15cd7fd5091b6bef54cb33b4c6fe563e3b9c4ec5
e8563827b8103f02a6505e7d02b99aae7881bbbd861d28bc5f0cddf56234
fe194f85d538034a2f3d5f88f5c03b49ccda1c4a4ba22419407b79bd3d0f
b0ccc8cc22ff3b3a6019130d67a2d6aa193d31fcc24cdc34830f31
~~~
