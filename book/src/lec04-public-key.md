# Enkripcija i razmena ključa

## Definicija problema

> Ana i Boban se nalaze na udaljenim krajevima planete i žele da uspostave
> enkriptovanu komunikaciju preko javnog kanala. Potrebno im je da uspostave
> zajednički tajni ključ za simetričnu enkripciju. Kako to mogu da urade?

<!-- TODO: Formalno uvesti Enc i Dec -->
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
def generate_keys():
  a = secrets.randbelow(p-2) + 1
  A = pow(g, a, p)
  return a, A

def shared_key(a, B):
  return pow(B, a, p)
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

Kada Boban želi da pošalje poruku Ani, on generiše slučajni broj \\(r\\) iz
skupa \\(\{1, 2, \ldots, q-1\}\\). Na osnovu Aninog javnog ključa računa
zajdnički Difi-Helman ključ \\(k = A^r\\). Poruku \\(m \in G\\) šifruje množenjem sa
\\(k\\) i kao šifrat šalje par vrednosti \\((c_{1}=R, c_{2}=km)\\) gde je \\(R
= g^r\\).

~~~python
def encrypt(m, A):
  r, R = dh.generate_keys()
  k = dh.shared_key(r, A)
  return R, (k * m) % dh_p
~~~

Ana dešifruje poruku tako što računa \\(c_{1}^a = R^a = k\\) i zatim deli
\\(c_{2}=km\\) sa \\(k\\) u grupi \\(G\\).

~~~python
def decrypt(R, c, a):
  k = dh.shared_key(a, R)
  return (c * pow(k, -1, dh_p)) % dh_p
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

Korisnik (Ana) generiše svoj par privatnog i javnog ključa na sledeći način.
Bira dva pseudoslučajna velika prosta broja \\(p\\) i \\(q\\) i računa \\(n =
pq\\) i \\(\varphi(n) = (p-1)(q-1)\\). Zatim bira broj \\(1 < e < \varphi(n)\\)
koji je uzajamno prost sa \\(\varphi(n)\\) i računa \\(d\\) takvo da je \\(d
\equiv e^{-1} \mod \varphi(n)\\). Javni ključ je par \\((n, e)\\), a privatni
ključ je broj \\(d\\). Vrednosti \\(p\\), \\(q\\) i \\(\varphi(n)\\) se
odbacuju i ne smeju biti javno dostupni.

~~~python
def generate_keys():
    p = number.getPrime(1024)
    q = number.getPrime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 0
    while math.gcd(e, phi) != 1:
        e = secrets.randbelow(phi - 2) + 2
    d = pow(e, -1, phi)

    return d, (n, e)
~~~

Kada Boban želi da pošalje poruku \\(0 \leq m < n\\) Ani, on koristi njen javni ključ za
šifrovanje poruke tako što računa \\(c = m^e \mod n\\). Ana dešifruje poruku
korišćenjem svog privatnog ključa računajući \\(m = c^d \mod n\\).

~~~python
def encrypt(m, e, n):
    return pow(m, e, n)

def decrypt(c, d, n):
    return pow(c, d, n)
~~~

Korektnost RSA kriptosistema dolazi iz toga što \\(m^{ed} \equiv m \mod
n\\):

Pokažimo da \\(m^{ed} \equiv m \mod p\\) (i potpuno analogno \\(m^{ed} \equiv m
\mod q\\)).

 1. Ako je \\(m\\) deljivo sa \\(p\\), tada je \\(m^{ed} \equiv 0 \equiv m \mod p\\).

 1. U suprotnom je \\(m^{p-1} \equiv 1 \mod p\\) po maloj Fermaovoj teoremi,
    pa je \\(m^{ed} = m^{1 + k\varphi(n)} = m^{1+k(p-1)(q-1)} =
    m(m^{p-1})^{k(q-1)} \equiv m \mod p\\).

 Kako je \\(m^{ed} \equiv m \mod p\\) i \\(m^{ed} \equiv m \mod q\\), po
 kineskoj teoremi o ostacima važi \\(m^{ed} \equiv m \mod n\\).

Primetimo da se bezbednost RSA kriptosistema oslanja na težinu narednog
problema:

> Odrediti broj \\(m\\) takav da je \\(m^e \equiv c\mod n\\).

Drugim rečima, potrebno je odrediti \\(e\\)-ti koren broja \\(c\\) po modulu
\\(n\\). Najefikasniji trenutno poznati algoritmi za rešavanje ovog problema se
oslanjaju na faktorizaciju broja \\(n\\). Naime, ako je poznato \\(n=pq\\),
lako je izračunati \\(\varphi(n)\\) i odrediti \\(d \equiv e^{-1} \mod
\varphi(n)\\). Onda je \\(m \equiv c^d \mod n\\).

Jedan problem sa direktnom primenom RSA kriptosistema je što se ista poruka
uvek šifruje u isti šifrat. Zato je potrebno na neki način proširiti poruku
pseudoslučajnim bitovima pre šifrovanja. Naglasimo da je u nastavku prikazan
način proširivanja poruka nebezbedan i da se u praksi koriste složenije šeme.

~~~python
def pad(m):
    # Jedan bajt lufta na početku
    padded_bytes = secrets.token_bytes(15) + m.to_bytes(240, "big")
    return int.from_bytes(padded_bytes, "big")

def unpad(m):
    padded_bytes = m.to_bytes(255, "big")
    return int.from_bytes(padded_bytes[15:], "big")

def encrypt(m, e, n):
    return pow(pad(m), e, n)

def decrypt(c, d, n):
    return unpad(pow(c, d, n))
~~~


## Zadaci

### Zadatak 1

Implementirati protokol koji omogućava klijentu i serveru da ostvare šifrovanu
komunikaciju. Tajni ključ se uspostavlja Difi-Helman razmenom. Nakon toga se
komunikacija nastavlja korišćenjem AES enkripcije za slanje poruka serveru.

### Zadatak 2

Ana i Boban izvršavaju Difi-Helman razmenu ključa:

~~~python
A = 524347013556703057489464193864
B = 672823340861902417431101467671
~~~

Eva kontroliše kanal i izvršava man-in-the-middle napad koristeći privatni ključ:

~~~python
e = 580068529088705669745084345056
~~~

Odrediti zajedničke ključeve koje Eva deli sa Anom i Bobanom ako su dati
parametri protokola:

~~~python
p = 804455613497485373990731588387
g = 2
~~~

### Zadatak 3

Klijenti se povezuju na server kako bi razmenjivali poruke. Prilikom
povezivanja, izvršavaju Difi-Helman razmenu ključa, nakon čega nastavljaju da
razmenjuju poruke koristeći AES enkripciju. Implementirati server koji izvršava
man-in-the-middle napad i prisluškuje komunikaciju između klijenata.

### Zadatak 4

Implementirati protokol koji omogućava klijentu i serveru da ostvare šifrovanu
komunikaciju. Klijent generiše tajni ključ, enkriptuje ga ElGamal šifrom i šalje
ga serveru. Nakon toga se komunikacija nastavlja korišćenjem AES enkripcije za
slanje poruka serveru.

### Zadatak 5

Parametri ElGamalovog kriptosistema su:

~~~python
p = 804455613497485373990731588387
g = 2
~~~

Poznato je da se poruka \\(m = 12\\) šifruje u:

~~~python
c1 = 93756064469162765164392542609
c2 = 50862892537411255160254263767
~~~

Odrediti poruku \\(m'\\) čiji je šifrat:

~~~python
c1 = 93756064469162765164392542609
c2 = 432677049653990478219958834048
~~~

### Zadatak 6

Implementirati protokol koji omogućava klijentu da preuzme šifrovanu datoteku
sa servera. Server generiše tajni ključ, enkriptuje ga RSA šifrom i šalje ga
klijentu. Zatim koristi taj ključ za enkripciju datoteke AES šifrom i šalje ga
klijentu.

### Zadatak 7

Korišćen je RSA bez proširivanja poruke sa javnim ključem \\(e = 5\\) i
\\(n=3225125342650157137441747827309271008554774656669170316841\\). Odrediti
poruku \\(m\\) ako je poznato da se ona šifruje u
\\(c=28294245410257430463566908142983628480617221151082271843\\).

### Zadatak 8

Korišćen je RSA sa proširivanjem poruke definisanim u nastavku. 

~~~python
def pad(m):
    r = secrets.randbits(32)
    return (m << 16) | r

def unpad(m):
    return m >> 16

def encrypt(m, e, n):
    return pow(pad(m), e, n)

def decrypt(c, d, n):
    return unpad(pow(c, d, n))
~~~

Odrediti poruku \\(m\\) šiforvanu javnim ključem \\(e = 5\\) i \\(n =
3225125342650157137441747827309271008554774656669170316841\\) ako je poznato da
se ona šifruje u \\(c = 414092455629355891057474807003843764215360074118451854843\\).

