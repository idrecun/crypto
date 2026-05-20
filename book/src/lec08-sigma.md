# Sigma protokoli i Fiat–Šamir heuristika

## Opis problema

> Ana želi da dokaže Bobanu da zna neku vrednost \\(x\\) koja predstavlja
> rešenje nekog NP problema, bez otkrivanja same vrednosti \\(x\\).

## Sigma protokoli

Podsetimo se jednog sigma protokola koji smo već upoznali. U pitanju je Šnorov
protokol identifikacije, kojim dokazivač dokazuje da za javno \\(A\\) poznaje
tajnu vrednost \\(a\\) takvu da je \\(A = g^a\\) u grupi \\(G\\) reda \\(n\\).

Protokol se sastoji od tri koraka:
1. Dokazivač se obavezuje na slučajnu vrednost \\(r \in \mathbb{Z}_n\\) tako
   što objavljuje \\(c = g^r\\).
2. Proveravač šalje izazov \\(e \in \mathbb{Z}_n\\).
3. Dokazivač otkriva vrednost \\(s = r + a e \mod n\\).

Proveravač se može uveriti da dokazivač zna tajnu vrednost \\(a\\) proveravajući da li
važi \\(g^s = c A^e\\).

Uopšteno, sigma protokoli su interaktivni protokoli između dokazivača i
proveravača koji se sastoje od tri koraka: obavezivanja, izazova i otkrivanja.
U prvom koraku, dokazivač se obavezuje na neku vrednost, koja je na neki način
povezana sa tajnom vrednošću. Zatim, proveravač šalje izazov, koji je obično
neka slučajna vrednost. Na kraju, dokazivač otkriva informaciju koja zavisi od
izazova i tajne vrednosti, a proveravač koristi tu informaciju da proveri da li
dokazivač zaista zna tajnu vrednost. Zbog toga što ovakvi protokoli ne otkrivaju
nikakvu informaciju o tajnoj vrednosti koju dokazivač poseduje, nazivaju se
protokolima sa *nula znanja* (eng. *zero-knowledge*).

## Fiat–Šamir heuristika

Fiat-Šamir heuristika je metoda za transformaciju interaktivnog sigma protokola
u neinteraktivni dokaz sa nula-znanja. Pretpostavimo da imamo sigma protokol
koji dokazuje poznavanje neke tajne vrednosti \\(a\\) koja je svedok za
instancu \\(A\\) nekog NP problema, i neka su njegova tri koraka:
1. Dokazivač se obavezuje na neku vrednost \\(x\\) objavljivanjem obaveze \\(c\\).
2. Proveravač šalje slučajan izazov \\(e\\).
3. Dokazivač otkriva neku vrednost \\(s\\) koja zavisi od \\(x\\) i \\(e\\).

Postavlja se pitanje: da li dokazivač može sam sebi, na neki fer način, da zada
izazov \\(e\\)? To bi zahtevalo da je \\(e\\) pseudoslučajna vrednost, kao i da
je poznata tek nakon objavljivanja obaveze \\(c\\). Ovo je moguće postići
korišćenjem heš funkcije. Konkretno, dokazivač računa izazov kao \\(e =
h(c)\\). Na taj način, dokazivač ne može da namesti izazov, jer on zavisi od
obaveze \\(c\\). Neinteraktivni dokaz se onda sastoji od trojke vrednosti
\\((A, c, s)\\). Napomenimo da se u praksi obično hešira kompletan transkript
protokola do trenutka izazova, odnosno \\(e = h(A, c)\\).

Primenom Fiat-Šamir heuristike na Šnorov protokol dobijamo Šnorov potpis:
1. Dokazivač se obavezuje na slučajnu vrednost \\(r \in \mathbb{Z}_n\\) tako što
   objavljuje \\(c = g^r\\).
2. Računa izazov kao \\(e = h(A, m, c)\\) (u transkript ulaze javni ključ, poruka i obaveza).
3. Računa potpis kao \\(s = r + a e \mod n\\). Proveravač se uverava da važi \\(g^s = c A^e\\).

## Pedersenovo obavezivanje

Videli smo da je moguće realizovati obavezivanje na neku vrednost \\(x\\)
pomoću heš funkcije. Još jedan način da konstruišemo šemu obavezivanja je
oslanjajući se na problem diskretnog logaritma.

### Definicija

Neka je \\(G\\) ciklična grupa reda \\(n\\), a \\(g\\) i \\(h\\) dva njena
generatora. Naglasimo da je neophodno da nije poznato \\(a\\) za koje važi
\\(g^a = h\\) (iako takvo \\(a\\) mora da postoji). Pedersen obavezivanje na
vrednost \\(x\\) računamo tako što biramo slučajno \\(0 \leq r < n\\) i
objavljujemo vrednost \\(c = g^x h^r\\). Kada želimo da otkrijemo vrednost
\\(x\\), potrebno je da otkrijemo i vrednost \\(r\\).

Čak i ako je skup mogućih vrednosti na koje se korisnik obavezuje mali,
nije moguće otkriti vezanu vrednost. Primetimo da ovo ne zavisi od težine
problema diskretnog logaritma, već samo od činjenice da je raspodela vrednosti
\\(g^x h^r\\) uniformna u \\(G\\) i da ne zavisi od \\(x\\) (ako je \\(r\\)
zaista slučajno odabrano).

Sa druge strane, ako bi korisnik koji objavljuje obavezu hteo da se obaveže na
jednu vrednost \\(x\\), a zatim otkrije drugu vrednost \\(x'\\), to bi
zahtevalo da može da odredi \\(x\\), \\(r\\), \\(x'\\) i \\(r'\\) takve da je
\\(g^x h^r = g^{x'} h^{r'}\\), odnosno \\(g^{x - x'} = h^{r' - r}\\). Kako je
\\(g^a = h\\) za neko \\(a\\), to znači da je potrebno pronaći vrednosti takve
da je \\(a = \frac{x - x'}{r' - r}\\), ali ovo bi upravo bilo rešenje problema
diskretnog logaritma.

Pedersenove obaveze imaju dva korisna svojstva koja heš obaveze ne poseduju.

### Homomorfizam

Neka je \\(x + y = z\\) (za skriveno \\(x\\) i \\(y\\) i javno \\(z\\)), i neka
su \\(c_x = g^x h^{r_x}\\) i \\(c_y = g^y h^{r_y}\\) obavezivanja na \\(x\\) i
\\(y\\). Tada je \\(c_x c_y = g^x h^{r_x} g^y h^{r_y} = g^{x+y} h^{r_x + r_y} =
g^z h^{r_x + r_y}\\) obaveza na \\(z\\). Ako korisnik otkrije vrednost \\(r_x +
r_y\\), bilo ko može da proveri da se on obavezao na vrednosti \\(x\\) i
\\(y\\) takve da je \\(x + y = z\\) bez otkrivanja samih vrednosti \\(x\\) i
\\(y\\). Dovoljno je proveriti da li je \\(c_x c_y = g^z h^{r_x + r_y}\\).

### Rerandomizacija

Neka je \\(c = g^x h^r\\) obaveza na \\(x\\). Tada je, za proizvoljno \\(r'\\),
vrednost \\(c' = c h^{r'} = g^x h^{r + r'}\\) takođe obaveza na \\(x\\).
Ovo omogućava korisnicima koji ne znaju vrednost \\(x\\) da generišu novu
obavezu na istu vrednost \\(x\\). To je korisno u protokolima gde je potrebno
"promešati" obaveze više korisnika, kako bismo uklonili vezu između korisnika i
njihovih obaveza.

Konkretnije, neka je \\(k\\) korisnika redom objavilo obaveze \\(c_1, \dots,
c_k\\) na vrednosti \\(x_1, \dots, x_k\\). Moguće je promeniti redosled obaveza
i rerandomizovati svaku od njih tako da se dobije novi skup obaveza \\(c_1',
\dots, c_k'\\) na iste vrednosti. Na osnovu samog skupa \\(c_1', \dots,
c_k'\\) nije moguće zaključiti koji se korisnik vezuje za koju vrednost.

## Zadaci

### Zadatak 1
 
Opisati sigma protokol za dokazivanje poznavanja rešenja problema 3-bojenja
grafa. Transformisati ga u neinteraktivan dokaz pomoću Fiat–Šamir heuristike.
Implementirati obe varijante.

### Zadatak 2
izomorfizam grafova

### Zadatak 3
hamiltonov ciklus

### Zadatak 4
sudoku

### Zadatak 5
shuffle + rerandomize

### Zadatak 6
magicni kvadrat

### Zadatak 7
zbirovi po kolonama i vrstama

### Zadatak 8
~~~
 abc
+abc
----
abcd
~~~

## Rešenja

### Zadatak 1

Pretpostavimo da dokazivač zna jedno 3-bojenje grafa \\(G\\). Pokušajmo da
konstruišemo sigma protokol na sledeći način:

1. Dokazivač se obavezuje na to bojenje tako što se obaveže na boju svakog
   čvora (\\(n\\) obavezivanja za \\(n\\) čvorova).
2. Proveravač šalje izazov za otkrivanje određene grane grafa (sa idejom da ako
   je 3-bojenje ispravno, onda boje u čvorovima te grane moraju biti
   različite).
3. Dokazivač otkriva boje čvorova na toj grani.

Jasno je da je ovakav protokol nepotpun. Sa jedne strane, dokazivač otkriva deo
bojenja u trećem koraku. Sa druge strane, proveravač ne može biti siguran da
dokazivač zaista zna validno bojenje. Moguće je da se dokazivač obavezao na
neko nevalidno bojenje koje izgleda validno za većinu grana, u nadi da će
proveravač izabrati granu koja ne otkriva grešku.

Oba nedostatka protokola se mogu otkloniti. Verovatnoća da dokazivač može
pravilno da odgovori na izazov, a da se pritom nije obavezao na validno
3-bojenje grafa, opada eksponencijalno sa svakim ponavljanjem protokola.
Dovoljno je ponoviti protokol npr. \\(k=1000\\) puta kako bi lažiranje dokaza
bilo praktično nemoguće. Kako dokazivač ne bi otkrio nikakvu informaciju o bojenju,
pre svakog ponavljanja menja bojenje slučajnim permutovanjem boja (na primer
svi čvorovi obojeni crvenu postaju plavi i obrnuto). Na taj način, jedinu
informaciju koju proveravač dobija je da su boje različite, ali ne i koje su
boje (početnog bojenja) u pitanju. Dakle, ispravljen protokol izgleda ovako:

Protokol se ponavlja \\(k\\) puta.
1. Dokazivač određuje slučajnu permutaciju bojenja i na nju se obavezuje.
2. Proveravač šalje izazov za otkrivanje određene grane grafa.
3. Dokazivač otkriva boje čvorova na toj grani.

Protokol transformišemo Fiat-Šamir heuristikom tako da dokazivač generiše
izazove pomoću heš funkcije. Konkretno, dokazivač se obavezuje na \\(k\\)
bojenja, a izazove generiše kao \\((e_1, \ldots, e_k) = h(G, c_1, \ldots,
c_k)\\) gde su \\(c_1, \ldots, c_k\\) pomenuta obavezivanja. Primetimo da je
neophodno heširati sva obavezivanja istovremeno. U suprotnom, ako bismo izazov
u svakom ponavljanju generisali nezavisno, dokazivač koji ne zna validno
bojenje bi mogao da namesti svaki pojedinačni izazov relativno jednostavno -
dovoljno je da pronađe bojenje čiji izazov bira jednu od grana čiji su krajevi
različiti. Ovo onda vraća isti problem koji smo imali sa prvobitnim pokušajem
protokola.

### Zadatak 2

Pretpostavimo da dokazivač zna izomorfizam između dva grafa \\(G_0\\) i
\\(G_1\\). Možemo konstruisati sigma protokol na sledeći način:

Protokol se ponavlja \\(k\\) puta.
1. Dokazivač objavljuje graf \\(C\\) izomorfan sa \\(G_0\\) i \\(G_1\\),
   dobijen slučajnim permutovanjem jednog od njih (sam graf \\(C\\) posmatramo
   kao obavezu).
2. Proveravač šalje izazov \\(e=0\\) ili \\(e=1\\).
3. Dokazivač otkriva izomorfizam između \\(C\\) i \\(G_e\\).

Za jednu iteraciju protokola, dokazivač koji ne zna izomorfizam između
\\(G_0\\) i \\(G_1\\) bi mogao da pokuša da lažira dokaz tako što se obaveže na
slučajnu permutaciju jednog od grafova, i da se nada da će proveravač odabrati
odgovarajući izazov. Verovatnoća da uspešno lažira dokaz je \\(\frac{1}{2}\\)
za jednu iteraciju, odnosno \\(\frac{1}{2^k}\\) za \\(k\\) iteracija. Sa druge strane,
proveravač ne može da zaključi ništa o izomorfizmu između \\(G_0\\) i \\(G_1\\)
jer i ako zna npr. izomorfizam između \\(C\\) i \\(G_0\\), ne zna izomorfizam
između \\(C\\) i \\(G_1\\).

Transformaciju u neinteraktivni dokaz vršimo tako što dokazivač objavljuje
\\(k\\) slučajnih grafova \\(C_1, \dots, C_k\\) izomorfnih sa \\(G_0\\) i
\\(G_1\\). Zatim generiše izazove \\(e_1, \dots, e_k\\) kao bitove heš
vrednosti \\(h(G_0, G_1, C_1, \dots, C_k)\\). Na kraju, dokazivač otkriva
izomorfizam između \\(C_i\\) i \\(G_{e_i}\\) za svako \\(i\\).

### Zadatak 3

Pretpostavimo da dokazivač zna Hamiltonov ciklus u grafu \\(G\\). Možemo
konstruisati sigma protokol na sledeći način:

Protokol se ponavlja \\(k\\) puta.
1. Dokazivač bira slučajnu permutaciju grafa \\(G\\) i obavezuje se na tako
   permutovanu matricu povezanosti (svako polje matrice je jedna obaveza).
2. Proveravač šalje izazov \\(e=0\\) ili \\(e=1\\).
3. Ukoliko je \\(e=0\\), dokazivač otkriva celu matricu povezanosti i
   permutaciju. Ukoliko je \\(e=1\\), dokazivač otkriva samo grane Hamiltonovog
   ciklusa u permutovanom grafu.

Za jednu iteraciju protokola, dokazivač koji ne zna Hamiltonov ciklus u grafu
mogao bi da pokuša da lažira dokaz ili tako što se obaveže na slučajnu
permutaciju grafa i da se nada da će proveravač odabrati izazov \\(e=0\\), ili
tako što se obaveže na proizvoljan graf koji ima Hamiltonov ciklus i da se nada
da će proveravač odabrati izazov \\(e=1\\). Verovatnoća da uspešno lažira dokaz
u \\(k\\) iteracija je \\(\frac{1}{2^k}\\).

Proveravač ne može da zaključi ništa o Hamiltonovom ciklusu u datom grafu. U
slučaju izazova \\(e=0\\) on vidi jedino permutovan graf \\(G\\), a u slučaju
izazova \\(e=1\\) on vidi samo da neki graf ima Hamiltonov ciklus, ali ne i
koji je to graf.

Transformaciju u neinteraktivni dokaz vršimo tako što se dokazivač obavezuje na
\\(k\\) slučajnih permutacija grafa \\(G\\) i generiše izazove \\(e_1, \dots,
e_k\\) kao bitove heš vrednosti \\(h(G, c_1, \dots, c_k)\\) gde su \\(c_1,
\dots, c_k\\) pomenuta obavezivanja.

### Zadatak 4

Pretpostavimo da dokazivač zna rešenje Sudoku slagalice. Možemo konstruisati sigma
protokol na sledeći način:

Protokol se ponavlja \\(k\\) puta.
1. Dokazivač bira slučajnu permutaciju brojeva od 1 do 9, na osnovu permutacije
   menja vrednosti u rešenju i obavezuje se na tako permutovano rešenje (svako
   polje je jedna obaveza).
2. Proveravač šalje jedan od mogućih izazova:
    - Otkrivanje svih vrednosti u određenom redu
    - Otkrivanje svih vrednosti u određenoj koloni
    - Otkrivanje svih vrednosti u određenom 3x3 kvadratu
    - Otkrivanje svih početnih vrednosti
3. Dokazivač otkriva tražene vrednosti.

Za jednu iteraciju protokola, dokazivač koji ne zna rešenje bi mogao da se
obaveže na neko nevalidno rešenje i da se nada da će proveravač odabrati izazov
koji ne otkriva grešku. U najboljem slučaju, verovatnoća da uspešno lažira
dokaz je \\(\frac{27}{28}\\) (ako konstruiše rešenje koje uspešno prolazi sve
osim jednog izazova). Za \\(k=1000\\), verovatnoća da uspešno lažira dokaz je
reda veličine \\(10^{-16}\\).

Jedino što proveravač saznaje u svakoj iteraciji je ili da su vrednosti u nekom
redu, koloni ili 3x3 kvadratu validne, ili da su početne vrednosti validne.

Transformaciju u neinteraktivni dokaz vršimo tako što se dokazivač obavezuje na
\\(k\\) slučajnih permutacija rešenja sudokua. Izazove generiše na osnovu heš
vrednosti \\(h(S, c_1, \dots, c_k)\\) gde je \\(S\\) početno stanje sudokua, a
\\(c_1, \dots, c_k\\) obaveze.

### Zadatak 5

Pretpostavimo da dokazivač zna mešanje koje transformiše niz Pedersenovih
obaveza \\(P_0 = (c^0_1, \dots, c^0_k)\\) u niz obaveza \\(P_1 = (c^1_1, \dots,
c^1_k)\\). Protokol možemo konstruisati na sličan način kao i protokol za
izomorfizam grafova:

Protokol se ponavlja \\(k\\) puta.
1. Dokazivač generiše i objavljuje slučajno mešanje \\(C\\) niza obaveza \\(P_0\\).
2. Proveravač šalje izazov \\(e=0\\) ili \\(e=1\\).
3. Dokazivač otkriva mešanje između \\(C\\) i \\(P_e\\).

Za jednu iteraciju protokola, dokazivač koji ne zna mešanje između \\(P_0\\) i
\\(P_1\\) bi mogao da pokuša da lažira dokaz ili tako što se obaveže na
slučajno mešanje niza \\(P_0\\) ili \\(P_1\\) i da se nada da će proveravač
odabrati odgovarajući izazov. Jasno, za \\(k\\) iteracija je verovatnoća da
uspešno lažira dokaz \\(\frac{1}{2^k}\\).

Transformaciju u neinteraktivni dokaz vršimo tako što dokazivač objavljuje
\\(k\\) slučajnih mešanja \\(C_1, \dots, C_k\\) niza obaveza \\(P_0\\). Zatim
generiše izazove \\(e_1, \dots, e_k\\) kao bitove heš vrednosti \\(h(P_0, P_1,
C_1, \dots, C_k)\\). Na kraju, dokazivač otkriva mešanje između \\(C_i\\) i
\\(P_{e_i}\\) za svako \\(i\\).

### Zadatak 6

Pretpostavimo da dokazivač zna rešenje magičnog kvadrata. Označimo sa \\(P_0\\)
niz \\(g^{i}\\) za \\(1 \leq i \leq n^2\\). Rešenje magičnog kvadrata možemo
predstaviti kao niz, a dokazivač se onda obavezuje na svaki element rešenja
nizom obaveza \\(P_1\\). Primetimo da se niz \\(P_1\\) može predstaviti kao
jedno mešanje niza \\(P_0\\). Dokazivač ovo dokazuje protokolom iz zadatka 5,
što znači da su vrednosti u njegovom rešenju zaista vrednosti \\(1, \dots,
n^2\\). Kako bi dokazao da su zbirovi po vrstama, kolonama i dijagonalama
jednaki \\(S = \frac{n(n^2 + 1)}{2}\\), može koristiti homomorfizam
Pedersenovih obaveza. Na primer, ako su \\(c_{i, 1}, \dots, c_{i, n}\\) obaveze
jedne vrste iz \\(P_1\\), dokazivač objavljuje vrednost \\(r_i = r_{i, 1} +
\dots + r_{i, n}\\) i proveravač proverava da li je \\(c_{i, 1} \cdots c_{i, n}
= g^S h^{r_i}\\). Na sličan način dokazivač dokazuje zbirove za sve ostale
vrste, kolone i dijagonale.

<!-- helios voting? -->
