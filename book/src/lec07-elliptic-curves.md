# Eliptičke krive

## Opis problema

> Da li postoji bolji izbor grupe \\(G\\) od \\(\mathbb{Z}_p^*\\) u protokolima
> kriptografije javnog ključa zasnovaniom na problemu diskretnog logaritma?

Eliptičke krive nam daju potvrdan odgovor na prethodno pitanje.

## Eliptičke krive nad \\(\mathbb{R}\\)

Posmatrajmo za početak eliptičke krive u skupu realnih brojeva. To su krive
određene skupom tačaka koje ispunjavaju jednakost \\(y^2 = x^3 + ax + b\\), za
neke \\(a, b \in \mathbb{R}\\). Kako kriva ne bila degenerisana, potebno je da
važi \\(4a^3 + 27b^2 \neq 0\\).

![Eliptičke krive](images/ec.png)

Skup tačaka eliptičke krive \\(E\\) zadate pomenutom jednakošću označavamo sa
\\(E(\mathbb{R})\\). Pretpostavljamo da pored tačaka koje zadovoljavaju
pomenutu jednakost postoji i "beskonačno daleka tačka" \\(\mathcal{O}\\) (ovo
je posledica toga da eliptičku krivu zapravo definišemo u projektivnoj ravni).

~~~python
def on_curve(P):
  if P is None:
    return True
  x, y = P
  return (y * y - x * x * x - a * x - b) % p == 0
~~~

<!-- ### Izvođenje Vajerštrasove forme -->

### Sabiranje tačaka

Na skupu tačaka \\(E(\mathbb{R})\\) možemo definisati operaciju sabiranja. Neka
su \\(P\\) i \\(Q\\) dve tačke na eliptičkoj krivoj. Prava kroz \\(P\\) i
\\(Q\\) seče krivu u nekoj trećoj tački \\(R\\). Sabiranje definišemo tako da
važi \\(P + Q + R = \mathcal{O}\\). Na slici su prikazana četiri različita
slučaja u zavisnosti od odnosa tačaka. U prvom slučaju su sve tri tačke
različite, u drugom je \\(P = Q\\), u trećem je \\(R = \mathcal{O}\\), a u
četvrtom je \\(P = Q\\) i \\(R = \mathcal{O}\\).

![Sabiranje tačaka na eliptičkoj krivoj](images/ec_add.png)

Na osnovu ovoga možemo izvesti formule za sabiranje tačaka na eliptičkoj
krivoj. Ako je \\(P = \mathcal{O}\\) onda je \\(P + Q = Q\\), a ako je \\(Q =
\mathcal{O}\\) onda je \\(P + Q = P\\). Drugim rečima, \\(\mathcal{O}\\) je
neutral za sabiranje tačaka.

Neka su date koordinate različitih tačaka \\(P: (x_P, y_P)\\) i \\(Q: (x_Q,
y_Q)\\). Ako je \\(x_P = x_Q\\), onda mora biti \\(y_P = -y_Q\\) (jer su tačke
različite), pa je \\(P + Q = \mathcal{O}\\). U suprotnom, računamo nagib prave
kroz \\(P\\) i \\(Q\\) kao \\(s = \frac{y_Q - y_P}{x_Q - x_P}\\). Za svaku tačku
na pravoj kroz \\(P\\) i \\(Q\\) važi \\(y - y_P = s(x - x_P)\\), a za svaku
tačku preseka sa krivom važi \\(y^2 = x^3 + ax + b\\). Zamenom prve jednačine u
drugu dobijamo jednačinu \\((sx - sx_P + y_P)^2 = x^3 + ax + b\\) po \\(x\\).
Ova jednačina ima tri rešenja (za tri tačke preseka) i njihove vrednosti su
\\(x_P\\), \\(x_Q\\) i \\(x_R\\). Po Vijetovim formulama važi \\(-(x_P + x_Q +
x_R) = -s^2\\). Kako je \\(P + Q = -R\\), koordinate zbira su \\(x_R = s^2 -
x_P - x_Q\\) i \\(y_R = -(s(x_R - x_P) + y_P)\\).

U slučaju da je \\(P = Q\\), \\(s\\) računamo kao nagib tangente na krivu u
tački \\(P\\). Ovo računamo diferenciranjem obe strane jednačine krive, odnosno
\\(\frac{d}{dx}y^2 = \frac{d}{dx}(x^3 + ax + b)\\). Dobijamo \\(2y
\frac{dy}{dx} = 3x^2 + a\\), odnosno \\(s = \frac{dy}{dx} = \frac{3x_P^2 +
a}{2y_P}\\).

~~~python
def neg(P):
  if P is None:
    return None
  return (P[0], (-P[1]) % p)

def add(P, Q):
  if P is None:
    return Q
  if Q is None:
    return P
  if P == neg(Q):
    return None
  x1, y1 = P
  x2, y2 = Q
  if x1 != x2:
    s = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
  else:
    s = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
  x3 = (s * s - x1 - x2) % p
  y3 = (s * (x1 - x3) - y1) % p
  return (x3, y3)

def sub(P, Q):
  return add(P, neg(Q))
~~~

### Množenje skalarom

Na osnovu sabiranja možemo jednostavno definisati množenje tačke prirodnim
brojem. Izveli smo formule za \\(2P = P + P\\). Jasno je da onda možemo
izračunati i \\(3P = 2P + P\\), \\(4P = 3P + P\\), itd. Ako bismo na ovaj način
računali \\(nP\\), složenost bi bila \\(O(n)\\). Umesto ovoga, možemo primeniti
isti algoritam kao za efikasno stepenovanje, čija je složenost \\(O(\log n)\\).

~~~python
def mul(k, P):
  R = None
  Q = P
  while k > 0:
    if k & 1:
      R = add(R, Q)
    Q = add(Q, Q)
    k >>= 1
  return R
~~~

## Eliptičke krive nad \\(\mathbb{F}_q\\)

Eliptičke krive možemo definisati i nad konačnim poljem \\(\mathbb{F}_q\\) na
isti način, pri čemu su sve vrednosti iz \\(\mathbb{F}_q\\). Za razliku od
eliptičkih kriva nad realnim brojevima, eliptičke krive nad konačnim poljima
nemaju jasnu geometrijsku strukturu. Ovo ih čini pogodnim za upotrebu u
kriptografiji.

![Eliptičke krive nad konačnim poljima](images/ec_fp.png)

Poznato je da je broj tačaka \\(n\\) na eliptičkoj krivoj nad
\\(\mathbb{F}_q\\) ograničen sa \\(|n - (q + 1)| \leq 2\sqrt{q}\\). Ovaj
rezultat je poznat kao Haseova teorema.

Problem diskretnog logaritma na eliptičkim krivama je problem rešavanja
jednačine \\(xG = H\\) gde su \\(G, H \in E(\mathbb{F}_q)\\). Za razliku od
problema diskretnog logaritma u \\( \mathbb{Z}_p^* \\), najefikasniji algoritmi
za njegovo rešavanje imaju eksponencijalnu složenost \\(O(\sqrt{n})\\) gde je
\\(n\\) veličina grupe. Zbog ovoga, u \\(E(\mathbb{F}_q)\\) je moguće koristiti
znatno manje ključeve nego u \\(\mathbb{Z}_p^*\\).

## Enkodovanje poruke na eliptičkoj krivoj

Kako bismo koristili eliptičke krive u kriptografiji, potrebno je da imamo
način da preslikamo proizvoljnu poruku \\(m\\) u tačku na eliptičkoj krivoj, i
obrnuto. Prikazaćemo jedan od načina koje je opisao Koblic.

Pretpostavimo da radimo sa krivom \\(E(\mathbb{F}_p)\\) za prost broj \\(p\\)
takav da je \\(p \equiv 3 \mod 4\\). Neka je broj \\(m\\) poruka koju želimo da
enkodujemo. Uzmimo na primer \\(k = 1024\\) i posmatrajmo redom vrednosti
\\(x_i = km + i\\) za \\(0 \leq i < k\\). Tražimo prvu vrednost \\(x_i\\) takvu
da je \\(c_i = x_i^3 + ax_i + b\\) kvadrat u \\(\mathbb{F}_p\\). Na osnovu
Ojlerovog kriterijuma, \\(c_i\\) je kvadrat po modulu \\(p\\) ako i samo ako je
\\(c_i^{\frac{p-1}{2}} \equiv 1 \mod p\\). Ako je \\(c_i\\) kvadrat, onda
njegov koren možemo izračunati kao \\(y_i = c_i^{\frac{p+1}{4}} \mod p\\) (zato
što je onda \\(y_i^2 = (c_i^{\frac{p+1}{4}})^2 = c_i^{\frac{p+1}{2}} =
c_i^{\frac{p-1}{2}}c_i \equiv c_i \pmod p\\)), što nam daje tačku \\((x_i,
y_i)\\) na krivoj. Kako je polovina brojeva kvadrat u \\(\mathbb{F}_p\\), jako
je mala šansa da \\(c_i\\) nije kvadrat ni za jedno \\(i\\). Sa druge strane,
za datu tačku \\((x, y)\\) jednostavno određujemo poruku \\(m\\) kao \\(\lfloor
\frac{x}{k} \rfloor\\).

~~~python
k = 1024

def encode(m):
  for i in range(k):
    x = m * k + i
    c = (x * x * x + a * x + b) % p
    if pow(c, (p - 1) // 2, p) == 1:
      y = pow(c, (p + 1) // 4, p)
      return (x, y)

def decode(P):
  return P[0] // k
~~~

## Protokoli zasnovani na eliptičkim krivama

Kao javni parametar bilo kog protokola potrebno je odabrati eliptičku krivu nad
nekim konačnim poljem. Biraju se parametri \\(p\\), koji određuje konačno
polje, \\(a, b \in \mathbb{F}_p\\) koji određuju krivu, tačka \\(G \in
E(\mathbb{F}_p)\\) koja je generator ciklične podgrupe i broj \\(n\\) koji
predstavlja red te podgrupe. Obično se objavljuje i broj \\(h=\frac{ \\#
E(\mathbb{F}_p)}{n}\\) koji predstavlja indeks podgrupe \\(\langle G \rangle
\\). Podgrupa se bira tako da je \\(n\\) veliki prost broj, kako protokol ne
bi bio podložan napadima (npr. poput Polig-Helmanovog algoritma).

### Generisanje i validacija ključeva

Generisanje ključeva funkcioniše kao i u do sada opisanim protokolima
zasnovanim na problemu diskretnog logaritma. Za tajni ključ bira se slučajan
broj \\(a \in \{1, \ldots, n-1\}\\), a javni ključ se računa kao \\(A = aG\\).

Kada korisnik prihvati nečiji javni ključ, potrebno je da proveri da li je on
validan. To podrazumeva da je ta tačka \\(A\\) zaista na krivoj, da nije tačka
u beskonačnosti i, u slučaju da je \\(h > 1\\), da pripada podgrupi generisanoj
tačkom \\(G\\).

~~~python
def generate_keys():
  a = secrets.randbelow(n - 2) + 1
  A = ec.mul(a, G)
  return a, A

def validate(A):
  if A is None:
    return False
  if not ec.on_curve(A):
    return False
  return ec.mul(n, A) is None
~~~

### Difi-Helman razmena ključa

Oba korisnika šalju svoj javni ključ drugom korisniku. Ako korisnik ima svoj
privatni ključ \\(a\\) i prihvatio je javni ključ drugog korisnika \\(B\\),
računa zajednički ključ kao \\(K = aB\\).

~~~python
def shared_key(a, B):
  return ec.mul(a, B)
~~~

### ElGamal enkripcija

Šifrovanje se vrši tako što prvo generišemo slučajan broj \\(r\\) iz skupa
\\(1, \ldots, n-1\\) i izračunamo tačku \\(R = rG\\). Ove vrednosti
predstavljaju privremeni privatni i javni ključ za Difi-Helman razmenu.
Računamo zajednički ključ \\(K = rA\\) gde je \\(A\\) javni ključ primaoca.
Poruka \\(m\\) koju šifrujemo se enkoduje u tačku \\(M\\) na krivoj i šifrat se
računa kao \\(C = M + K\\). Šalje se par vrednosti \\((R, C)\\).

Dešifrovanje se vrši tako što primalac računa zajednički ključ kao \\(K = aR\\)
i dešifruje poruku kao \\(M = C - K\\), koju napokon dekoduje iz tačke u
vrednost \\(m\\).

~~~python
def encrypt(M, A):
  r, R = ecdh.generate_keys()
  K = ecdh.shared_key(r, A)
  return R, ec.add(M, K)

def decrypt(R, C, a):
  K = ecdh.shared_key(a, R)
  return ec.sub(C, K)
~~~

### ElGamal potpis

Za potpisivanje poruke \\(m\\) bira se slučajan broj \\(r\\) iz skupa \\( 1,
\ldots, n-1\\) i računa se tačka \\(R = rG\\). Ako potpisujemo poruku privatnim
ključem \\(a\\), potpis se računa kao \\(s = r^{-1}(h(m) - a \phi(R)) \mod
n\\), gde sada za \\(\phi\\) biramo preslikavanje iz skupa tačaka eliptičke
krive u vrednost iz \\(\mathbb{Z}\\), konkretno \\(\phi(R) = R_x\\).

Provera potpisa se vrši proverom jednakosti \\(h(m)G = sR + \phi(R) A\\).
Ukoliko je potpis validan, onda važi \\(sR + \phi(R)A = (rs + a\phi(R))G =
(rr^{-1}(h(m) - a \phi(R)) + a \phi(R))G = h(m)G\\).

~~~python
def phi(R):
  return R[0] % n

def sign(m, a):
  s = 0
  while s == 0:
    r = 0
    while math.gcd(r, n) != 1:
      r = secrets.randbelow(n - 1) + 1
    R = ec.mul(r, G)
    s = (pow(r, -1, n) * (hash(m) - a * phi(R))) % n
  return (R, s)

def verify(m, R, s, A):
  return ec.mul(hash(m), G) == ec.add(ec.mul(s, R), ec.mul(phi(R), A))
~~~

### Šnorov potpis

Za potpisivanje poruke \\(m\\) bira se slučajan broj \\(r\\) iz skupa \\( 1,
\ldots, n-1\\) i računa se tačka \\(R = rG\\). Izazov se računa kao \\(c =
h(R_x, R_y, m)\\), a potpis se računa kao \\(s = r + ac \mod n\\).

Provera potpisa se vrši proverom jednakosti \\(sG = R + cA\\). Ukoliko je
potpis validan, onda važi \\(sG = (r + ac)G = rG + acG = R + cA\\).

~~~python
def sign(m, a):
  r = secrets.randbelow(n - 1) + 1
  R = ec.mul(r, G)
  c = hash(str(R) + m) % n
  s = (r + a * c) % n
  return (R, s)

def verify(m, R, s, A):
  c = hash(str(R) + m) % n
  return ec.mul(s, G) == ec.add(R, ec.mul(c, A))
~~~

## Zadaci

U narednim zadacima, ukoliko nije drugačije naznačeno, koristi se kriva
*secp128r1* sa parametrima:

~~~python
p = 340282366762482138434845932244680310783
a = 340282366762482138434845932244680310780
b = 308990863222245658030922601041482374867
G = (29408993404948928992877151431649155974,
     275621562871047521857442314737465260675)
n = 340282366762482138443322565580356624661
~~~

### Zadatak 1

Implementirati protokol koji omogućava klijentu i serveru da ostvare šifrovanu
komunikaciju. Tajni ključ se uspostavlja ECDH razmenom. Nakon toga se
komunikacija nastavlja korišćenjem AES enkripcije za slanje poruka serveru.

### Zadatak 2

Ana i Boban izvršavaju ECDH razmenu ključa. Njihovi javni ključevi su:

~~~python
A = (38908903211101888278623563709835614940,
     86414223312395224141852774166062813584)
B = (210067491220345722062217915833545932319,
     314595414076388517941891137742153277344)
~~~

Eva kontroliše kanal i izvršava man-in-the-middle napad koristeći privatni ključ:

~~~python
e = 99327691616788894527576870712013829048
~~~

Odrediti zajedničke ključeve koje Eva deli sa Anom i Bobanom.

### Zadatak 3

Anin javni EC-ElGamal ključ je:

~~~python
A = (172555618972274937527774535265768735313,
     10081883194550683330255804375487986898)
~~~

Poznato je da se poruka enkodovana kao tačka:

~~~python
M = (258195427694994240236789828875940887457,
     337184816232937204958887835705857507231)
~~~

šifruje u:

~~~python
R1 = (70317932819526710602903815804549240940,
      36813546415559138349030471247361636124)
C1 = (287066134838516450567688517941084959058,
      218063401705308332321934229482059355773)
~~~

Odrediti poruku \\(M'\\) (kao tačku) čiji je šifrat:

~~~python
R2 = (70317932819526710602903815804549240940,
      36813546415559138349030471247361636124)
C2 = (33302374266159024897512879673930207502,
      336771186098399155523098592439895884956)
~~~

### Zadatak 4

Boban koristi EC-ElGamal potpis sa \\(\phi(R) = R_x\\). Bobanov javni ključ je:

~~~python
A = (1446342285746087496322261997989149864,
     51899882338286411277127986568238557735)
~~~

Poznate su poruke `m1 = "Hello, world!"` sa potpisom:

~~~python
R1 = (91407655570239612505893793489075498927,
      25538088875613710856623369771771322160)
s1 = 311396362683851534909632246027045848057
~~~

i `m2 = "Hello, matf!"` sa potpisom:

~~~python
R2 = (91407655570239612505893793489075498927,
      25538088875613710856623369771771322160)
s2 = 32731572252507648075677496446020975539
~~~

Odrediti privatni ključ.

### Zadatak 5

Boban koristi EC-Šnorov potpis u kome se izazov računa na sledeći način:

~~~python
def challenge(R, m):
  b = f"({R[0]},{R[1]})".encode() + m
  return int.from_bytes(hashlib.sha256(b).digest(), "big") % n
~~~

Bobanov javni ključ je:

~~~python
A = (109467063707252142941786888194056392558,
     283624804562688076124413520142906544564)
~~~

Poznate su poruke `m1 = "Zdravo, svete!"` sa potpisom:

~~~python
R1 = (69191772370633742414484574291592789683,
      150081736994045835000962439583877754103)
s1 = 275532418724142788316051765718430826437
~~~

i `m2 = "Vozdra, svete!"` sa potpisom:

~~~python
R2 = (69191772370633742414484574291592789683,
      150081736994045835000962439583877754103)
s2 = 22127400428374188013866090255927965142
~~~

Odrediti privatni ključ.

### Zadatak 6

Boban koristi EC-Šnorov potpis u kome se izazov računa kao \\(c = h(m) \mod
n\\). Bobanov javni ključ je:

~~~python
A = (246691936285505052706352817197487175489,
     10886859581935478975083534919891668598)
~~~

Predstaviti se lažno kao Boban i poslati Ani potpisanu poruku
`m = "Vozdra, svete!"`.

### Zadatak 7

Implementirati protokol koji omogućava klijentu i serveru da ostvare šifrovanu
komunikaciju razmenom ECDH ključeva. Obezbediti da je protokol otporan na
man-in-the-middle napade korišćenjem EC-Šnorovog potpisa.

### Zadatak 8

Boban koristi ECDH protokol nad krivom \\(y^2 = x^3 + 1\\) nad poljem
\\(\mathbb{F}_p\\) sa parametrima:

~~~python
p = 1940158473524142299
n = 1940158473524142300
G = (17, 213329057279393933)
~~~

Bobanov javni ključ je:

~~~python
A = (1057509392935454215, 1290626223251531797)
~~~

Odrediti Bobanov privatni ključ.
