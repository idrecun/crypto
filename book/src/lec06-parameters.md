# Izbor parametara

## Opis problema

> Na koji način se generišu i biraju veliki prosti brojevi za potrebe protokola
> kriptografije javnog ključa?

## Generisanje velikih prostih brojeva

Glavni pristup za generisanje velikih prostih brojeva je, možda neočekivano,
generisati veliki pseudoslučajni broj (npr. reda veličine 1000 bitova) i
ispitati da li je tako generisan broj prost.

Broj prostih brojeva manjih ili jednakih \\(x\\) označava se sa \\(\pi(x)\\).
Poznato je da se \\(\pi(x)\\) asimptotski ponaša kao \\(\frac{x}{\log x}\\),
što znači da je verovatnoća da je slučajno odabran broj manji ili jednak
\\(x\\) prost okvirno \\(\frac{1}{\log x}\\). Drugim rečima, ako pokušavamo da
generišemo prost broj sa 1000 bitova, potrebno nam je reda veličine 1000
pokušaja da generišemo prost broj.

Sa druge strane, poznato je da je problem ispitivanja da li je broj prost rešiv
u polinomijalnom vremenu u odnosu na broj bitova. Najbolji trenutno poznat
algoritam je AKS test, čija je vremenska složenost \\(O(\log^6 n)\\). Sa druge
strane, postoje probabalistički testovi koji su mnogo brži, sa kompromisom da
postoji mala verovatnoća da proglase složen broj prostim. Jedan takav test je
Miler-Rabin test.

### Miler-Rabin test

Podsetimo se male Fermaove teoreme:

> Neka je \\(p\\) prost broj i \\(0 < a < p\\). Tada važi \\(a^{p-1} \equiv 1
> \mod p\\).

Jedan pokušaj da konstruišemo probabalistički test je da za dato \\(n\\)
odaberemo nasumično \\(1 < a < n - 1\\) i proverimo da li važi \\(a^{n-1}
\equiv 1 \mod n\\). Ukoliko kongruencija ne važi, onda je \\(n\\) složen broj.
Pretpostavka je da ako odaberemo dovoljno različitih \\(a\\) i izvršimo ovu
proveru za svako od njih, možemo sa velikom verovatnoćom biti sigurni da je
\\(n\\) prost. Nažalost, postoji klasa složenih brojeva, tzv. Karlmajklovi
brojevi, koji zadovoljavaju ovu kongruenciju za svako \\(a\\) koje je uzajamno
prosto sa \\(n\\).

~~~python
def fermat_test(n, k):
  for _ in range(k):
    a = random.randint(2, n - 2)
    if pow(a, n - 1, n) != 1:
      return False
  return True
~~~

Test možemo poboljšati oslanjajući se na dodatno zapažanje:

> Ako je \\(p\\) prost broj, tada je \\(\mathbb{Z}_p\\) polje. Konkretnije, to
> znači da su jedina rešenja kongruencije \\(x^2 \equiv 1 \mod p\\) brojevi
> \\(1\\) i \\(-1\\).

Predstavimo \\(n-1\\) kao \\(2^s d\\). Jasno je da ako važi \\(a^{n-1} \equiv 1
\mod n\\), onda počevši od nekog \\(j\\) važi i \\(a^{2^rd} \equiv 1 \mod n\\)
za svako \\(j \leq r \leq s\\). Ukoliko je \\(j > 0\\) i \\(a^{2^{j-1}d}
\not\equiv -1 \mod n\\), onda \\(\mathbb{Z}_n\\) ne može biti polje, zato što
je \\((a^{2^{j-1}})^2 \equiv a^{2^jd} \equiv 1 \mod n\\), odnosno zato što je
\\(a^{2^{j-1}d}\\) rešenje kongruencije \\(x^2 \equiv 1 \mod n\\).

Posmatrajmo nekoliko primera. Ako je \\(n = 21\\), broj \\(n-1=20\\)
predstavljamo kao \\(2^2 \cdot 5\\) i posmatramo stepene \\(x_0 = 5, x_1 = 10,
x_2 = 20\\). Odgovarajući ostaci \\(a^{5}, a^{10}, a^{20} \mod n\\) za \\(a =
8\\) su \\(8, 1, 1\\), pa \\(n=21\\) mora biti složen broj jer je \\(8^2 \equiv
1 \mod 21\\). Ako, sa druge strane, posmatramo prost broj \\(n = 13\\) i \\(a =
3\\), niz ostataka \\(a^{3}, a^{6}, a^{12} \mod n\\) je \\(1, 1, 1\\). Za \\(a
= 2\\) dobijamo niz \\(2, -1, 1\\).

Miler-Rabinov test za odabrano \\(a\\) proverava redom vrednosti \\(a^{2^rd}
\equiv 1 \mod n\\) za \\(0 \leq r \leq s\\). Broj proglašavamo složenim ako ne
pronađemo vrednost 1 (zbog male Fermaove teoreme) ili ako pronađemo 1 ali
prethodna vrednost (ukoliko postoji) nije -1. Može da se desi da odabrano
\\(a\\) prođe test iako je \\(n\\) složen broj. Zbog toga, bira se \\(k\\)
slučajnih brojeva \\(a\\) i test se ponavlja za svaki od njih. Za razliku od
Fermaovog testa, poznato je da svaki složen broj \\(n\\) ima najviše
\\(\frac{1}{4}\\) ovakvih "lažnih svedoka". Prema tome, verovatnoća da složen
broj proglasimo prostim nakon \\(k\\) ponavljanja testa je najviše
\\(\frac{1}{4^k}\\).

~~~python
def test(a, s, d, n):
  x = pow(a, d, n)
  if x == 1:
    return True
  for r in range(s):
    t = x
    x = pow(x, 2, n)
    if x == 1:
      return t == n - 1
  return False

def miller_rabin(n, k):
  if n <= 1:
    return False
  if n <= 3:
    return True
  if n % 2 == 0:
    return False

  s, d = 0, n - 1
  while d % 2 == 0:
    d //= 2
    s += 1

  for _ in range(k):
    a = random.randint(2, n - 2)
    x = pow(a, d, n)
    if not test(a, s, d, n):
      return False

  return True
~~~

Složenost algoritma je \\(O(k \cdot \log^3 n)\\) ako se za množenje velikih
brojeva koristi naivni \\(O(\log^2 n)\\) algoritam.

## Napadi na loše izabrane parametre

Postoji veliki broj algoritama za rešavanje problema faktorizacije i problema
diskretnog logaritma. Neki od njih imaju značajno manju vremensku složenost u
zavisnosti od strukture ulaznih brojeva.

Definišimo \\(b\\)-gladak broj (eng. \\(b\\)-powersmooth):

> Broj \\(n\\) je \\(b\\)-gladak ako su mu svi stepeni prostih faktora manji
> ili jednaki \\(b\\), odnosno ako je \\(n = p_1^{e_1} \cdots p_k^{e_k}\\) i
> \\(p_i^{e_i} \leq b\\) za svako \\(i\\).

### Polardov \\(p-1\\) algoritam za faktorijzaciju

Neka \\(p\\) deli \\(n\\). Tada za bilo koji broj \\(x\\) deljiv sa \\(p\\)
važi da je \\(\gcd (x, n)\\) takođe deljivo sa \\(p\\). Primetimo da je broj
oblika \\(a^{k(p-1)} - 1\\) deljiv sa \\(p\\) za bilo koje \\(1 < a < p\\) i
\\(k \geq 1\\), na osnovu male Fermaove teoreme. Ukoliko je \\(p - 1\\)
\\(b\\)-gladak, to znači da je \\(M=\operatorname{lcm} (1, \ldots, b)\\) deljiv
sa \\(p-1\\) (jer sadrži sve stepene prostih brojeva manje ili jednake \\(b\\),
odnosno \\(M = k(p-1)\\) za neko \\(k\\). Ukoliko je \\(1 < \gcd (a^M - 1, n) <
n \\), tada je \\( \gcd (a^M - 1, n)\\) netrivijalni delilac broja \\(n\\).

Algoritam funkcioniše na sledeći način. Biramo osnovu \\(a\\), npr. \\(a =
2\\). Redom računamo \\(M_i = \operatorname{lcm} (1, \dots, i)\\) i za svaku
iteraciju račuanmo \\(g = \gcd (a^{M_i} - 1, n)\\). Ukoliko je \\(1 < g < n\\),
vraćamo \\(g\\) kao rezultat. Ukoliko nismo pronašli takvo \\(g\\), možemo
pokušati ili sa drugom granicom \\(b\\) ili osnovom \\(a\\). U slučaju da je
\\(g = n\\), veća vrednost za \\(M\\) neće pomoći, pa u tom slučaju treba ili
promeniti osnovu \\(a\\) ili prijaviti neuspeh.

~~~python
def pollard_p1(n, a, b):
  M = 1
  for i in range(2, b + 1):
    M = math.lcm(M, i)
    g = math.gcd(pow(a, M, n) - 1, n)
    if g == n:
      return None
    if g > 1:
      return g
  return None
~~~

Napomenimo da ova implementacija nije optimalna. Umesto ovoga, mogli bismo da
računamo \\(M\\) množenjem svih stepena prostih brojeva manjih ili jednakih
\\(b\\). Pošto je ovu operaciju moguće raditi po modulu \\(n\\), ne bi bilo
potrebe da radimo sa velikim brojevima, pa je ova varijanta nešto brža.

~~~python
def sieve(n):
  is_prime = [True] * (n + 1)
  is_prime[0] = is_prime[1] = False
  for i in range(2, n):
    if is_prime[i]:
      for j in range(i * i, n + 1, i):
        is_prime[j] = False
  return [i for i in range(n + 1) if is_prime[i]]

def pollard_p1(n, a, b):
  for p in sieve(b):
    t = 1
    while t * p <= b:
      t = t * p
    a = pow(a, t, n)
    g = math.gcd(a - 1, n)
    if g == n:
      return None
    if g > 1:
      return g
  return None
~~~

U obe varijante složenost algoritma zavisi od \\(b\\) i od \\(\log n\\).
Ako je \\(n=pq\\) za proste brojeve \\(p\\) i \\(q\\), i ako je \\(p-1\\)
\\(b\\)-gladak za relativno malo \\(b\\), moguće je efikasno rešiti problem
faktorizacije za \\(n\\) na ovaj način.

### Polig-Helmanov algoritam za diskretni logaritam

Neka je data ciklična grupa \\(G\\) reda \\(n\\) generisana elementom \\(g\\).
Potrebno je odrediti \\(x\\) tako da važi \\(g^x = h\\) za neko \\(h \in G\\).
Ako je poznata faktorizacija \\(n = p_1^{e_1} \cdots p_k^{e_k}\\), grupu \\(G\\)
je moguće razložiti na proizvod cikličnih grupa reda \\(p_i^{e_i}\\). Konkretno,
možemo posmatrati elemente \\(g_i = g^{n / p_i^{e_i}}\\). Red ciklične podgrupe
generisane elementom \\(g_i\\) je \\(p_i^{e_i}\\) (poznato je da je red bilo
kog elementa \\(g^k\\) u cikličnoj grupi jednak \\(\frac{n}{\gcd(n, k)}\\)).
Kako je \\(g^x = h\\), onda je \\(h_i = h^{n / p_i^{e_i}} = (g^x)^{n /
p_i^{e_i}} = g_i^x \in \langle g_i \rangle\\). Ako bismo rešili problem
diskretnog logaritma \\(g_i^x = h_i\\) u svakoj podgrupi, odredili bismo vrednost
\\(x \pmod{p_i^{e_i}}\\) za svako \\(i\\). Na osnovu kineske teoreme o ostacima
onda možemo jednostavno da odredimo i \\(x \pmod{n}\\).

Primetimo da ako je \\(n\\) (odnosno \\(p-1\\) u grupi \\(\mathbb{Z}_p^*\\))
\\(b\\)-gladak, onda je moguće efikasno rešiti problem diskretnog logaritma u
složenosti koja zavisi od \\(b\\) i od \\(\log n\\).

~~~python
def dlp_naive(g, h, n, p):
  t = 1
  for x in range(n):
    if t == h:
      return x
    t = (t * g) % p
  return None

# Radimo u grupi Z_p^* reda n = p - 1
def pohlig_hellman(g, h, p):
  x = 0
  n = p - 1
  for pi, ei in factors(n):
    ti = pi ** ei
    gi = pow(g, n // ti, p)
    hi = pow(h, n // ti, p)
    xi = dlp_naive(gi, hi, ti, p)
    x += xi * (n // ti) * pow(n // ti, -1, ti)
  return x % n
~~~

Naglasimo da je ovo samo osnovna verzija algoritma. Algoritam je moguće
proširiti da radi efikasno i ako je broj \\(n\\) takav da se sastoji od prostih
faktora manjih ili jednakih \\(b\\) (eng. \\(b\\)-smooth), što je slabiji uslov
od toga da su mu svi stepeni prostih faktora manji ili jednaki \\(b\\), ali ovo
nećemo razmatrati.

## Zadaci

### Zadatak 1

Ana Bobanu šalje poruku enkriptovanu pomoću RSA. Bobanov javni ključ je:

```
n = 128012969945026248732835279448470961755200314723736138420211480647446338936601
e = 45003644880317641650549332948458540440828733125352288665595332773107626216631
```

Odrediti poruku \\(M\\) ako je poznat šifrat:

```
C = 17804263439160944615212115660102150497899902713732968130942328933737091348102
```

### Zadatak 2

Bobanov javni RSA ključ je:

```
n = 7603286354234243903435872704677498363399458016631578496018195845589487786172473
e = 7535918899271596912605330771330141519800214292622992808169830647334620913196679
```

Predstaviti se lažno kao Boban i poslati Ani potpisanu poruku `M = 11111`.

### Zadatak 3

Ana i Boban razmenjuju tajni ključ pomoću Difi-Helmanovog protokola. Parametri
su:

```
g = 2
p = 7601624022030852444912481695317914837957
```

Javni ključevi su:

```
A = 2211695542287328335118624827317758656022
B = 6182657336541579015064991427667254728726
```

Odrediti tajni ključ.

### Zadatak 4

Ana Bobanu šalje poruku enkriptovanu pomoću ElGamalovog kriptosistema.
Parametri su:

```
g = 3
p = 1870481974960029238219966388771406118351
```

Bobanov javni ključ je:

```
B = 497191599874828811421853470900833470993
```

Odrediti poruku \\(M\\) ukoliko su poznati šifrat i Anin privremeni javni ključ:

```
C = 1473663585592763770030583068836711465092
A = 1343596286854575049094069011811221332574
```

### Zadatak 5

Boban koristi ElGamalov potpis sa parametrima:

```
g = 2
p = 4712211801531972521576351639088809533078043
```

Bobanov javni ključ je:

```
A = 764106831585898804754070363523847426400175
```

Predstaviti se lažno kao Boban i poslati Ani potpisanu poruku `M = "Hello,
matf!"`.

### Zadatak 6

Boban koristi Šnorov potpis sa parametrima:

```
g = 5
p = 102930135201232568905447342456556663645567
```

Bobanov javni ključ je:

```
A = 9662939937200861840582525885171675976500
```

Predstaviti se lažno kao Boban i poslati Ani potpisanu poruku `M = "Vozdra,
svete!"`.

### Zadatak 7

Boban je Ani ponudio nekoliko kandidata za parametar \\(p\\) Difi-Helmanovog
protokola. Odrediti koji su od ponuđenih kandidata bezbedni:

```
pA = 230914455703691489588482744432827805051
pB = 1100412499263221912937307421102321256919
pC = 275314703551481333360766958972593260039
pD = 293720665814433582927735487060431957427
```

### Zadatak 8

Implementirati funkciju koja generiše bezbedan prost broj \\(p\\) zadate
veličine.

