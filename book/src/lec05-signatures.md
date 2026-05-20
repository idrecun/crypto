# Digitalni potpisi

## Opis problema

> Ana želi da pošalje poruku Bobanu preko nebezbednog kanala. Ana i Boban
> nemaju zajednički tajni ključ. Kako Ana može da dokaže Bobanu da je poruka
> koju je poslala zaista potekla od nje?

<!-- TODO: formalnije uvesti Sign i Verify -->

Rešenje za problem autentifikacije nude digitalni potpisi. Svaki učesnik, kao i
u slučaju enkripcije, ima par javnog i privatnog ključa. Privatni ključ se
koristi za potpisivanje poruka, a bilo ko ko poznaje javni ključ može da
proveri da li je poruka potpisana odgovarajućim privatnim ključem.

## RSA potpis

Par ključeva koji se koriste za RSA potpisivanje se generiše na isti način kao
i kod RSA enkripcije. Poruku \\(m\\) možemo potpisati izračunavanjem potpisa
\\(s = m^d \mod n\\), gde je \\(d\\) privatni ključ. Za proveru potpisa,
koristimo javni ključ \\(e\\) i računamo \\(m' = s^e \mod n\\), nakon čega
proveravamo da li je \\(m' = m\\).

~~~python
def sign(m, d, n):
    return pow(m, d, n)

def verify(m, s, e, n):
    return m == pow(s, e, n)
~~~

Ukoliko bi napadač hteo da lažira potpis poruke \\(m\\), morao bi da pronađe
broj \\(s\\) tako da važi \\(s^e \equiv m \mod n\\). Ovo je isti problem na
čijoj težini se zasniva sigurnost RSA enkripcije.

Primetimo da prethodno opisan potpis nije ni praktičan, ni bezbedan. Veličina
poruke koju možemo potpisati ovakvim potpisom je ograničena brojem \\(n\\). Sa
druge strane, napadač može jednostavno da formira validan potpis za neku poruku
bez poznavanja tajnog ključa, ukoliko su mu poznate bar dve potpisane poruke
\\((m_1, s_1)\\) i \\((m_2, s_2)\\). Primetimo da je za poruku \\(m \equiv m_1 m_2
\mod n\\) vrednost \\(s \equiv s_1 s_2 \mod n\\) validan potpis jer je \\(s \equiv s_1
s_2 \equiv m_1^d m_2^d \equiv (m_1 m_2)^d \equiv m^d \mod n\\).

Kako bismo rešili oba problema, umesto direktne primene privatnog ključa na
poruku, možemo ga primeniti na heš vrednost poruke, odnosno \\(s \equiv h(m)^d
\mod n\\). Provera potpisa se onda vrši na isti način, pri čemu se potpis
proverava u odnosu na heš vrednost poruke.

~~~python
def sign(m, d, n):
    return pow(hash(m), d, n)

def verify(m, s, e, n):
    return hash(m) == pow(s, e, n)
~~~

Na ovaj način veličina poruke koju možemo potpisati nije ograničena. Sada,
ukoliko bi napadač hteo da iskoristi par potpisanih poruka da izvede napad,
jedino što bi mogao da izračuna je \\(s \equiv s_1 s_2 \equiv (h(m_1) h(m_2))^d
\mod n\\). Kako bi odredio poruku \\(m\\) za koju \\(s\\) predstavlja validan
potpis, moramo bi da pronadje vrednost takvu da je \\(h(m) \equiv h(m_1) h(m_2)
\mod n\\), odnosno morao bi da pronađe inverznu sliku heš funkcije, što
pretpostavljamo da je težak problem.

## ElGamal potpis

Slično kao i u slučaju enkripcije, u osnovi ElGamal potpisa je problem
diskretnog logaritma. Bira se ciklična grupa \\(G\\) reda \\(q\\) generisana
elementom \\(g\\), u kojoj je problem diskrenog logaritma težak, a par ključeva
se generiše na isti način. Bira se slučajan broj \\(a\\) iz skupa \\(\\{1,
\\ldots, q-1\\}\\) i računa se \\(A = g^a\\). Pretpostavljamo da potpisujemo
heš vrednost poruke \\(h(m)\\) kao i u slučaju RSA potpisa.

Za potpisivanje poruke \\(m\\) bira se slučajan broj \\(r\\) iz \\(
\mathbb{Z}_q^* \\) i računa se \\(R = g^r\\). Potpis se računa kao \\(s =
r^{-1}(h(m) - a \phi(R)) \mod q\\). Ovde \\(\phi\\) predstavlja proizvoljno
preslikavanje iz elemenata grupe \\(G\\) u skalare \\(\mathbb{Z}\\). Za tipičan
izbor grupe \\(G = \mathbb{Z}_p^*\\) uzima se jednostavno \\(\phi(R) = R\\), u
kom slučaju je \\(q=p-1\\) ako je \\(g\\) primitivni koren po modulu \\(p\\).

Provera potpisa se vrši proverom jednakosti \\(g^{h(m)} = R^s A^{\phi(R)}\\).
Ukoliko je potpis validan, onda važi \\(R^s A^{\phi(R)} = g^{rs + a \phi(R)} =
g^{rr^{-1}(h(m) - a \phi(R)) + a \phi(R)} = g^{h(m)}\\).

~~~python
def generate_keys():
  return dh.generate_keys()

def sign(m, a):
  s = 0
  while s == 0: # osiguravamo da s nije 0
    r = 0
    while math.gcd(r, q) != 1:
      r = secrets.randbelow(q-1) + 1
    R = pow(g, r, p)
    s = (pow(r, -1, q) * (hash(m) - a * R)) % q
  return (R, s)

def verify(m, R, s, A):
  return pow(g, hash(m), p) == (pow(R, s, p) * pow(A, R, p)) % p
~~~

Kako bismo bolje razumeli definiciju potpis, pokušajmo da ga konstruišemo korak
po korak. Ciljevi konstrukcije potpisa su:

1. Potpis mora biti vezan za poruku \\(m\\)
2. Autentičnost potpisa mora biti proveriva na osnovu javnog ključa \\(A\\)
3. Jedino onaj ko zna tajni ključ \\(a\\) može da konstruiše validan potpis
4. Iz potpisa ne sme biti moguće izvući tajni ključ \\(a\\)

Vrednost \\(s=h(m)-a\\) sama po sebi ispunjava prva tri svojstva: vezana je za
poruku \\(m\\), samo onaj ko zna vrednost \\(a\\) može da je izračuna i njena
autentičnost se jednostavno proverava na osnovu javnog ključa \\(A\\) -
dovoljno je proveriti da li važi \\(g^{h(m)} = g^sA\\). Naravno, potrebno je
ispuniti i poslednji cilj, odnosno ne otkriti vrednost \\(a\\).

Jedan način da pokušamo to da postignemo je da nekako zamaskiramo vrednost
\\(h(m)-a\\) slučajnim brojem. Odaberimo slučajnu vrednost \\(r\\) i
izračunajmo \\(s = r^{-1}(h(m)-a)\\). Ako bismo uz vrednost \\(s\\) proizveli i
vrednost \\(R = g^r\\), dobili bismo par vrednosti \\((R, s)\\) koji ispunjava
tri od četiri cilja. Autentičnost se može proveriti ispitivanjem jednakosti
\\(g^{h(m)}=R^sA\\). Iz ovih vrednosti nije moguće odrediti vrednost \\(a\\)
bez rešavanja problema diskretnog logaritma, jer je u najmanju ruku potrebno
odrediti vrednost \\(r\\). Nažalost, moguće je lako lažirati par vrednosti koji
ispunjava jednakost, npr. odabirom \\(R=g^{h(m)}A^{-1}\\) i \\(s=1\\).
Prethodni pokušaj onda možemo popraviti dodatnim maskiranjem vrednosti \\(a\\),
množenjem sa \\(\phi(R)\\) (odnosno \\(R\\)).

Napomenimo da kao i kod RSA potpisa, neophodno je potpis primeniti na heš
poruke. U suprotnom, napadač koji pokušava da lažira potpis treba da odredi
parametre tako da važi \\(g^m = R^s A^R\\). Jedan način da to izvede je da
odabere \\(R = Ag^e\\) za proizvoljno \\(e\\) i \\(s = -R\\). Tada jednakost
postaje \\(g^m = A^{-R}g^{-eR}A^R = g^{-eR}\\), pa je potpis \\((R, s)\\)
validan za poruku \\(m = -eR = es\\).

## Šnorov potpis

Šnorov potpis je još jedna konstrukcija potpisa zasnovana na problemu
diskretnog logaritma. Par ključeva se generiše na isti način kao i kod ElGamal
potpisa.

Upoznajmo prvo Šnorov protokol identifikacije. Pretpostavimo da Ana želi da
dokaže da je \\(A\\) zaista njen javni ključ, bez otkrivanja tajnog ključa
\\(a\\). Ana bira slučajan broj \\(r\\) i šalje Bobanu vrednost \\(R=g^r\\).
Boban bira slučajan broj \\(c \in \mathbb{Z}_q\\) (eng. *challenge*) i šalje ga
Ani. Broj \\(c\\) predstavlja "izazov" na koji Ana treba da odgovori. Ana
odgovara sa \\(s = r + ac \mod q\\). Boban proverava da li je \\(g^s = R
A^c\\). Ako je Ana iskrena, onda važi \\(RA^c = g^{(r+ac)} = g^s\\).

Recimo da Ana ne zna tajni ključ koji odgovara javnom ključu \\(A\\). Da bi
varala u protokolu, morala bi da izračuna vrednost \\(s\\) za proizvoljni
izazov \\(c\\), odnosno da odredi \\(s\\) tako da važi \\(g^s = RA^c\\). Kako
ne može unapred da zna vrednost izraza \\(RA^c\\), jedini način da pronađe
odgovarajuće \\(s\\) je da reši problem diskretnog logaritma. Sa druge strane,
jedini način da Boban otkrije Anin tajni ključ je da izračuna vrednost \\(r\\),
a da bi to uradio, morao bi da reši problem diskretnog logaritma.

Šnorov potpis se konstruiše kao neinteraktivna verzija Šnorovog protokola.
Ključno zapažanje je da Ana može sama sebi da generiše nepredvidiv izazov
\\(c\\) pomoću heš funkcije. Konkretno, bira \\(c = h(R || m)\\) gde je \\(m\\)
poruka koju želi da potpiše. Ovakva transformacija iz interaktivnog protokola u
neinteraktivni naziva se Fiat-Šamir transformacija.

Primetimo da u izazov mora da uđe i vrednost \\(R\\). U suprotnom, bilo ko bi
mogao da izračuna validan potpis za poruku \\(m\\) pažljivim izborom vrednosti
\\(R\\) (npr. \\(R = A^{-c}g^s\\) za proizvoljno \\(s\\)).

~~~python
def generate_keys():
  return dh.generate_keys()

def sign(m, a):
  r = secrets.randbelow(q-1) + 1
  R = pow(g, r, p)
  c = hash(str(R) + m) % q
  s = (r + a * c) % q
  return (R, s)

def verify(m, R, s, A):
  c = hash(str(R) + m) % q
  return pow(g, s, p) == (R * pow(A, c, p)) % p
~~~

<!-- TODO: Multisig? -->

## Zadaci

### Zadatak 1

Neka je RSA potpis implementiran na sledeći način:

~~~python
def sign(m, d, n):
    return pow(m, d, n)

def verify(m, s, e, n):
    return m == pow(s, e, n)
~~~

Poznate su poruke `m1=12345` sa RSA potpisom `s1=642633528765` i `m2=10000` sa
potpisom `s2=73743664084` za javni ključ `e = 262722871823` i `m =
780291688489`. Konstruisati novu poruku sa validnim RSA potpisom za taj javni
ključ.

### Zadatak 2

Poznate su poruke `m1=Hello, world!` sa ElGamal potpisom
`R1=337153912634787611310786958972`, `s1=203198881425351687104207477185` i
`m2=Hello, matf!` sa potpisom `R2=337153912634787611310786958972`,
`s2=678452672753114526815458651189`. Odrediti privatni ključ.

### Zadatak 3

Neka je ElGamalov potpis implementiran na sledeci nacin:

~~~python
def sign(m, a):
  s = 0
  while s == 0:
    r = 0
    while math.gcd(r, q) != 1:
      r = secrets.randbelow(q-1) + 1
    R = pow(g, r, p)
    s = (pow(r, -1, q) * (m - a * R)) % q
  return (R, s)

def verify(m, R, s, A):
  return pow(g, m, p) == (pow(R, s, p) * pow(A, R, p)) % p
~~~

Konstruisati poruku sa validnim potpisom za javni ključ
`A=335275883964444880445558231962`.

### Zadatak 4

Poznate su poruke `m1=Zdravo, svete!` sa Šnorovim potpisom
`R=183849108012164733417305462859`, `s1=548948698949370520837447260599` i
`m2=Vozdra, svete!` sa potpisom `R=183849108012164733417305462859`,
`s2=145102361266571118514964376433`. Javni ključ je
`A=537788132761577003712801186261`. Odrediti privatni ključ.

### Zadatak 5

Neka je Šnorov potpis implementiran na sledeći način:

~~~python
r = 1000

def sign(m, a):
  r += 1
  R = pow(g, r, p)
  c = challenge(R, m)
  s = (r + a * c) % q
  return (R, s)
~~~

Poznate su poruke `m1=Zdravo, svete!` sa Šnorovim potpisom
`R1=111363904694286227266861505255`, `s1=336143517230584486730326547926` i
`m2=Vozdra, svete!` sa potpisom `R2=729591181082362914015977546335`,
`s2=360002113235708705370255168750`. Javni ključ je
`A=537788132761577003712801186261`. Odrediti privatni ključ.

### Zadatak 6

Neka je Šnorov potpis implementiran na sledeći način:

~~~python
def challenge(m):
  h = hashlib.sha256(m).digest()
  return int.from_bytes(h, "big") % q
~~~

Konstruisati poruku sa validnim potpisom za javni ključ
`A=537788132761577003712801186261`.

### Zadatak 7

Implementirati protokol koji omogućava klijentu i serveru da ostvare šifrovanu
komunikaciju razmenom Difi-Helman ključeva. Obezbediti da je protokol otporan
na man-in-the-middle napade.

### Zadatak 8

Klijent se povezuje na server i preuzima najnoviju verziju softvera. Obezbediti
da klijent može da proveri autentičnost preuzetog softvera.

### Zadatak 9

Implementirati server koji omogućava klijentima da se prijave bez korišćenja
lozinke. Klijent dokazuje identitet izvršavanjem Šnorovog protokola
identifikacije sa serverom. Pretpostaviti da server unapred zna javni ključ
klijenta.

### Zadatak 10

Implementirati server koji izvršava transakcije prenosa novca između korisnika.
Server prihvata transakciju samo ako je potpisana potpisom korisnika koji
prenosi novac i ako korisnik ima dovoljno novca na računu. Pretpostaviti da
server unapred poznaje javne ključeve svih korisnika. Razmotriti napad ponovnim
slanjem i implementirati rešenje.

<!-- TODO za buducnost: mozda u zadacima imati jedan trusted public key koji
igra ulogu CA, i onda u svim zadacima gde se razmenjuju javni kljucevi, moguce
je koristiti javni kljuc potpisan od strane CA -->

<!--
Diffie-Hellman with signing
RSA combine signatures if no hash is used
ElGamal nonce reuse
ElGamal combine signatures if no hash is used  (!)
ElGamal forgery if no hash is used?  (!)
ElGamal s = 0?
Schnorr nonce reuse
Schnorr without R in hash
Signed software update protocol
ssh auth flow (sign challenge)
certificates
replay attack (currency transfer, solution - add nonce or timestamp)
-->
