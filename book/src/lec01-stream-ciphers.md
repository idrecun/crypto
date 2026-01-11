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
efikasni napadi na nju. Na primer, ako je dužina ključa \\(n\\) poznata, možemo
podeliti šifrovanu poruku u \\(n\\) grupa, gde svaka grupa sadrži karaktere
koji su šifrovani pomoću istog pomeraja. Na primer, ako pretpostavljamo da je
dužina ključa 3, onda delimo poruku `HELLOWORLD` u grupe `H..L..O..D`,
`.E..O..R..` i `..L..W..L.`. Za svaku grupu onda možemo primeniti analizu
učestalosti slova kao u Cezarovoj šifri da bismo otkrili odgovarajući pomeraj.

## Protočne šifre

## Zadaci

- zadatak gde se koristi protocna sifra sa premalim periodom
