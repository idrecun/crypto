# Heš funkcije i obavezivanja

## Definicija problema

> Ana ima neki podatak \\(m\\) koji želi kasnije da pošalje Bobanu, ali možda
> ne želi odmah da ga otkrije. Boban želi da dobije garanciju od Ane da, kada
> mu Ana konačno pošalje neki podatak (možda i pomoću nekog posrednika, Eve),
> on može nezavisno da se uveri da je zaista dobio podatak \\(m\\).

Kriptografska heš funkcija je kriptografska primitiva koja nam omogućava da
proizvoljnom podatku pridružimo kratak "otisak prsta". Formalnije,
kriptografksa heš funkcija preslikava proizvoljnu poruku \\(m\\) u niz bitova
\\(h(m)\\) fiksne dužine \\(n\\) (npr. 256), pri čemu mora da poseduje sledeća
svojstva:

1. *Otpornost na inverznu sliku*: Za dato \\(d\\) nije moguće pronaći poruku
   \\(m\\) tako da je \\(h(m) = d\\).
1. *Otpornost na drugu inverznu sliku*: Za dato \\(m\\) nije moguće pronaći
   poruku \\(m'\\) različitu od \\(m\\) tako da je \\(h(m) = h(m')\\).
1. *Otpornost na kolizije*: Nije moguće pronaći par različitih poruka \\(m\\) i
   \\(m'\\) tako da je \\(h(m) = h(m')\\).

U ovom kontekstu, izraz "nije moguće" znači da ne postoji algoritam koji može
da izračuna traženi rezultat u nekom razumnom vremenu.

## Konstrukcija heš funkcije

Konstrukcije kriptografskih heš funkcija se uglavnom zasnivaju na iterativnoj
primeni neke funkcije \\(f\\). Svojstva funkcije \\(f\\) se mogu razlikovati u
zavisnosti od konstrukcije.

### Merkle-Damgard konstrukcija

Merkle-Damgard konstrukcija koristi funkciju \\(f\\) koja preslikava par
blokova veličine \\(n\\) u blok veličine \\(n\\). Poruka \\(m\\) se deli na
blokove veličine \\(n\\) i računa se niz stanja \\(s_{i} = f(s_{i-1}, m_{i})\\)
pri čemu se za \\(s_0\\) uzima algoritmom definisan inicializacioni vektor. Za
vrednost funkcije \\(h(m)\\) se uzima poslednje stanje \\(s_k\\). Kako bi
funkcija \\(h\\) ispunjavala željena svojstva, dovoljno je da ih zadovoljava i
funkcija \\(f\\).

<!-- TODO -->
~~~python
~~~

Primetimo da dužina poruke \\(m\\) ne mora biti deljiva sa \\(n\\). U tom
slučaju je potrebno dopuniti poruku, npr. dodavanjem niza bitova oblika
`100...0`.

<!-- TODO -->
~~~python
~~~

### Sunđer konstrukcija

Sunđer konstrukcija se oslanja na funkciju \\(f\\) koja je bijekcija i koja ima
svojstva pseudoslučajne permutacije. Tokom konstrukcije održava se stanje \\(s
= [ r, c ]\\), gde \\(r\\) predstavlja deo stanja koji se direktno kombinuje
sa ulaznom porukom operacijom xor, dok \\(c\\) predstavlja unutrašnje stanje
heša.

Heš funkcija se dobija tako što se prvo "upija" poruka, odnosno tako što se
svaki blok poruke XOR-uje sa trenutnim \\(r\\). Između svaka dva bloka se
stanje \\([ r, c ]\\) transformiše funkcijom \\(f\\), odnosno \\(s_i = [r_i, c_i] =
f([r_{i-1} \oplus m_i, c_{i-1}])\\). Nakon upijanja svih blokova, vrednost heš
funkcije se "istiskuje", odnosno čitaju se blokovi iz \\(r\\) do željene dužine heš
vrednosti.

<!-- TODO -->
~~~python
~~~

## HMAC

## Identifikacija i integritet podataka

## Kriptografsko obavezivanje

## Zadaci

<!-- 0 padding -> break collision and second preimage resistance -->
