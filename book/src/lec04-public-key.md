# Enkripcija i razmena ključa

## Definicija problema

> Ana i Boban se nalaze na udaljenim krajevima planete i žele da uspostave
> enkriptovanu komunikaciju preko javnog kanala. Potrebno im je da uspostave
> zajednički tajni ključ za simetričnu enkripciju. Kako to mogu da urade?

Asimetrična kriptografija, odnosno kriptografija javnog ključa, je pristup koji
omogućava rešavanje prethodno opisanog problema. Osnovna ideja je da svaki
korisnik ima svoj privatni ključ, koji je tajni podatak, kao i svoj javni
ključ, koji je dostupan svima.

## Problemi u osnovi kriptografije javnog ključa

Izdvajamo dva problema na kojima se zasniva sigurnost protokola kriptografije
javnog ključa. Sigurnost dolazi iz predpostavke da su ovi problemi teški za
rešavanje, odnosno da ne postoji efikasan algoritam koji ih može rešiti u
razumnom vremenu.

### Problem faktorizacije

> Dat je prirodan broj \\(n\\). Odrediti prost broj \\(p\\) takav da \\(p \mid
> n\\).

Razmotrimo naivni algoritam za rešavanje ovog problema, koji proverava
deljivost broja \\(n\\) sa svim prirodnim brojevima manjim ili jednakim
\\(\sqrt{n}\\). Složenost ovog algoritma je \\(O(\sqrt{n})\\), što naizgled
nije loše. Ipak, ako je \\(n \approx 2^{1024}\\), odnosno ako ima reda veličine
1024 binarnih cifara, algoritam zahteva oko \\(2^{512}\\) koraka, što je
praktično neizvodljivo. Broj koraka je zapravo eksponencijalan u odnosu na
veličinu ulaza, tj. \\(O(\sqrt{2}^b)\\), gde je \\(b\\) broj bitova potrebnih
za predstavljanje broja \\(n\\). Postoje mnogo efikasniji algoritmi za
faktorizaciju, ali nijedan nije ni blizu polinomijalne vremenske složenosti i
svi su praktično neupotrebljivi za brojeve ove veličine.

### Problem diskretnog logaritma

> Data je konačna grupa \\((G, \cdot)\\) i elementi \\(a, b \in G\\). Odrediti
> prirodan broj \\(x\\) takav da je \\(a^x = b\\).

Često se koristi multiplikativna grupa \\((\mathbb{Z}_p^*, \cdot)\\), gde je
\\(p\\) prost broj. Slično problemu faktorizacije, u ovoj grupi postoji
relativno jednostavan algoritam koji ovaj problem rešava u vremenskoj
složenosti \\(O(\sqrt{p})\\), kao i napredniji algoritmi, ali takođe nisu
praktično upotrebljivi za dovoljno velike vrednosti \\(p\\). Napomenimo da
problem diskretnog logaritma nije težak u svim grupama. Na primer, u grupi
\\((\mathbb{Z}_p, +)\\) je trivijalan, jer se svodi na rešavanje kongruencije
\\(ax \equiv b \mod p\\).

## Difi-Helman protokol za razmenu ključa

Difi-Helman protokol je prvi objavljen protokol kriptografije javnog ključa.
Zasnovan je na problemu diskretnog logaritma i omogućava razmenu tajnog ključa
preko javnog kanala.

Parametri protokola su vrednosti koje su unapred odabrane tako da imaju
poželjna svojstva i dostupne su svim učesnicima. Konkretno, bira se ciklična
grupa \\(G\\) reda \\(q\\) i generator grupe \\(g\\). Tipičan izbor grupe je
\\(G = \mathbb{Z}_{p}^{*}\\) za prost broj \\(p\\), u kom slučaju je \\(g\\)
primitivni koren po modulu \\(p\\), a red grupe je \\(q = p-1\\). Primere
konkretnih vrednosti parametara \\(p\\) i \\(g\\) moguće je pronaći
[ovde](https://datatracker.ietf.org/doc/html/rfc3526).

Koraci protokola su sledeći:

1. Ana i Boban generišu svoje privatne ključeve \\(a\\) i \\(b\\) slučajnim
   odabirom iz skupa \\(\{1, 2, \ldots, q-1\}\\).
1. Ana računa svoj javni ključ \\(A = g^a\\) i šalje ga Bobanu. Boban
   radi isto sa svojim javnim ključem \\(B = g^b\\).
1. Ana računa zajednički tajni ključ \\(k = B^a\\), a Boban računa \\(k'
   = A^b\\).

Protokol je ispravan jer važi \\(k' = A^b = g^{ab} = B^a = k\\). Napadaču su
poznate vrednosti \\(p, g, A, B\\), ali ništa od ovoga nije dovoljno da
izračuna \\(k\\), osim rešavanjem problema diskretnog logaritma za \\(g^a=A\\)
ili \\(g^b=B\\).

~~~python
~~~

Jedan problem sa ovim protokolom je što je podložan tzv. *man-in-the-middle*
napadu. Recimo da Eva kontroliše kanal kojim Ana i Boban komuniciraju. Eva može
Ani da se predstavi kao Boban, i Bobanu da se predstavi kao Ana, i sa oboje
može da izvrši Difi-Helman razmenu ključa. Time dobija tajni ključ \\(k_{1}\\)
za komunikaciju sa Anom i tajni ključ \\(k_{2}\\) za komunikaciju sa Bobanom.
Kada Ana pošalje poruku Bobanu, ona je šifruje ključem \\(k_{1}\\), Eva je
prihvata i dešifruje, pročita, i šifruje ključem \\(k_{2}\\) pre nego što je
pošalje Bobanu. Na ovaj način, Eva može da prisluškuje i menja poruke između
Ane i Bobana bez njihovog znanja. U praksi, ovaj problem se rešava nekim vidom
autentifikacije, o čemu će biti reči u kasnijim lekcijama.

## ElGamal enkripcija

ElGamal enkripcija omogućava slanje šifrovanih poruka korišćenjem javnog
ključa. Svaki korisnik ima svoj privatni ključ i svoj javni ključ. Javni ključ
može bilo ko da koristi da šifruje poruke, a tako šifrovane poruke jedino može
da dešifruje korisnik koji poseduje privatni ključ.

U praksi se enkripcija javnim ključem koristi za šifrovanje malih poruka.
Najčešće se koristi za šifrovanje i slanje slučajno generisanog tajnog ključa
koji se zatim koristi za simetričnu enkripciju u ostatku komunikacije.

Slično kao kod Difi-Helman protokola, parametri protokola su ciklična grupa
\\(G\\) reda \\(q\\) i njen generator \\(g\\). Korisnik (Ana) generiše svoj
privatni ključ \\(a\\) slučajnim odabirom iz skupa \\(\{1, 2, \ldots, q-1\}\\)
i računa svoj javni ključ \\(A = g^a\\).

~~~python
~~~

Kada Boban želi da pošalje poruku Ani, on generiše slučajni broj \\(b\\) iz
skupa \\(\{1, 2, \ldots, q-1\}\\). Na osnovu Aninog javnog ključa računa
zajdednički Difi-Helman ključ \\(k = A^b\\). Poruku \\(m\\) šifruje množenjem
sa \\(k\\) i kao šifrat šalje par vrednosti \\((c_{1}=B, c_{2}=km))\\) gde je
\\(B = g^b\\).

~~~python
~~~

Ana dešifruje poruku tako što računa \\(c_{1}^a = B^a = k\\) i zatim deli
\\(c_{2}=km\\) sa \\(k\\) u grupi \\(G\\).

~~~python
~~~

ElGamal enkripcija se oslanja na Difi-Helman razmenu ključa i samim tim na
problem diskretnog logaritma za sigurnost.

Primetimo da upotreba ElGamal kriptosistema za razmenu tajnog ključa nije
podložan na man-in-the-middle napad na isti način kao Difi-Helman razmena
ključa. Razlog je što pretpostavljamo da je Anin javni ključ autentičan, ili
time što je poznat unapred, ili time što dolazi uz sertifikat garancije od
strane nekog pouzdanog autoriteta (eng. certificate authority).

## RSA (Rivest-Shamir-Adelman) enkripcija

RSA kriptosistem, slično ElGamalovom kriptosistemu, omogućava enkripciju poruka
korišćenjem javnog ključa. Za razliku od prethodnih protokola, RSA se oslanja
na problem faktorizacije.

## Zadaci

<!--
man in the middle
mali eksponent
elgamal nonce reuse
elgamal malleability
implementacije protokola (klijent/server)
-->
