# Deljenje tajni

## Šamirovo deljenje tajne

> Ana ima tajni ključ koji ne želi da čuva kod sebe. Umesto toga, želi da ga
> podeli na pet delova i svaki deo sakrije na posebno mesto (npr. kod kuće, u
> banci, kod prijatelja, itd.). Želi da na osnovu bilo koja tri dela može da
> rekonstruiše ceo tajni ključ (za slučaj da se neki delovi zagube), ali takođe
> da samo jedan ili dva dela ne otkrivaju ništa o tajnom ključu (za slučaj da
> je neki deo kompromitovan). Na koji način ona može to da uradi?

Posmatrajmo, na primer, polinom \\(f(x) = ax^2 + bx + c\\). Pretpostavimo da
koeficijenti \\(a\\), \\(b\\) i \\(c\\) nisu poznati, ali da su nam poznate
tačke \\((x_1, y_1), (x_2, y_2), \dots, (x_k, y_k)\\) kroz koje polinom
prolazi. Ako je broj poznatih tačaka manji ili jednak stepenu polinoma 2, nije
moguće odrediti koeficijente polinoma zato što postoji beskonačno mnogo
polinoma koji prolaze kroz te tačke. Sa druge strane, ako je broj tačaka veći
od stepena polinoma, moguće je tačno odrediti polinom.

Šamirovo deljenje tajni se zasniva upravo na prethodnom svojstvu polinoma. Neka
je \\(s \in \\mathbb{Z}_p\\) tajna vrednost i neka je potrebno podeliti je na
\\(n\\) delova, pri čemu je za rekonstrukciju tajne potrebno bar \\(t + 1\\)
delova. Biramo slučajan polinom \\(f(x)\\) stepena \\(t\\) takav da je \\(f(0)
= s\\). Delovi tajne se biraju kao \\((i, s_i)\\) gde je \\(s_i = f(i)\\) za
\\(1 \leq i \leq n\\).

Na osnovu \\(k = t + 1\\) delova \\((x_1, s_1), \dots, (x_k, s_k)\\), tajna se
može rekonstruisati pomoću Lagranžove interpolacije. Definišemo \\(l_1(x)\\)
kao polinom takav da je \\(l_1(x_1) = 1\\), odnosno \\(l_1(x_j) = 0\\) za
\\(j > 1\\). Jedan takav polinom je \\(l_1(x) = \frac{(x - x_2)\ldots(x -
x_k)}{(x_1 - x_2)\ldots(x_1 - x_k)}\\). Na sličan način možemo definisati i
polinome \\(l_2(x), \dots, l_k(x)\\). Tada je \\(f(x) = s_1 l_1(x) + \dots +
s_k l_k(x)\\), odakle se jednostavno rekonstruiše \\(s = f(0)\\).

~~~python
def eval_poly(coeffs, x):
    y = 0
    for c in reversed(coeffs):
        y = (y * x + c) % q
    return y

def share(s, t, n):
    coeffs = [s] + [secrets.randbelow(q) for _ in range(t)]
    return [(i, eval_poly(coeffs, i)) for i in range(1, n + 1)]

def lagrange(indices, x=0):
    coeffs = {}
    for i in indices:
        num, den = 1, 1
        for j in indices:
            if j != i:
                num = (num * (x - j)) % q
                den = (den * (i - j)) % q
        coeffs[i] = (num * pow(den, -1, q)) % q
    return coeffs

def reconstruct(parts):
    coeffs = lagrange([i for i, _ in parts])
    return sum(coeffs[i] * s_i for i, s_i in parts) % q
~~~

## Feldmanovo proverivo deljenje tajne

> Boban je izglasan da odabere i podeli tajni ključ grupi od pet ljudi.
> Potrebno je podeliti ključ na pet delova, tako da je moguće rekonstruisati ga
> na osnovu bilo koja tri dela, a da jedan ili dva dela ne otkrivaju ništa o
> tajnom ključu. Takođe, učesnici žele da mogu da provere da im Boban nije
> poslao nevažeće delove na osnovu kojih nije moguće rekonstruisati smislen
> ključ.

Feldmanovo deljenje tajne omogućava da svaki učesnik proveri da li je njegov
deo validan. Tajni polinom se konstruiše na isti način kao u Šamirovom deljenju
tajne, pri čemu se dodatno objavljuju obaveze koeficijenata polinoma. Ako je
polinom \\(f(x) = ax^2 + bx + c\\) u grupi \\(\mathbb{Z}_p\\) (primetimo da je
\\(c\\) tajna vrednost), onda se objavljuju obaveze \\(C_a = g^a, C_b = g^b,
C_c = g^c\\) u nekoj grupi \\(G\\) generisanoj elementom \\(g\\) reda \\(p\\).
Učesnik koji je dobio deo \\((i, s_i)\\) proverava da li je zaista \\(s_i =
f(i)\\), odnosno da li je \\(s_i = ai^2+bi+c\\) tako što proveri da li važi
\\(g^{s_i} = C_a^{i^2} C_b^i C_c\\). Primetimo da smo ovde koristili svojstvo
homomorfizma obaveza, slično kao kod Pedersenovog obavezivanja. Napomenimo i
da je moguće koristiti Pedersenova obavezivanja za nešto jača svojstva
protokola.

~~~python
def commit(coeffs):
    return [pow(g, c, p) for c in coeffs]

def verify(part, commitments):
    i, s_i = part
    rhs = 1
    for k, C in enumerate(commitments):
        rhs = (rhs * pow(C, i ** k, p)) % p
    return pow(g, s_i, p) == rhs
~~~

## Pedersenovo distribuirano generisanje ključa

> Grupa od \\(n\\) ljudi želi da generiše zajednički tajni ključ koji je moguće
> otkriti ukoliko se većina složi da to treba uraditi. Na koji način je to
> moguće uraditi?

Pedersenov protokol omogućava generisanje deljene tajne bez centralnog delioca.
Svaki učesnik \\(i\\) generiše slučajan polinom \\(f_i (x)=a _{i, 0} + a _{i,
1} x + \dots + a _{i, t} x^t\\) u grupi \\(\mathbb{Z}_p\\) i objavljuje njegove
obaveze \\(C _{i, 0}, \dots, C _{i, t}\\). Učesnik \\(i\\) šalje deo \\((j, s
_{i, j})\\) učesniku \\(j\\) (gde je \\(s _{i, j} = f_i(j)\\)), a učesnik
\\(j\\) proverava da li je zaista \\(s _{i, j} = f_i(j)\\) na isti način kao u
Feldmanovom deljenju tajne. Na kraju, svaki učesnik \\(i\\) računa svoj deo
tajne kao \\(s_i = s _{1, i} + \dots + s _{n, i}\\).

Primetimo da su na ovaj način učesnici odredili polinom \\(f(x) = f_1(x) +
\dots + f_n(x)\\) i da je tajna vrednost \\(s = f(0)\\), a da svaki učesnik
\\(i\\) poseduje deo \\((i, f(i))\\). Sa tim u vidu, rekonstrukcija tajne se
vrši na isti način kao u Šamirovom deljenju tajne.

~~~python
def run_dkg(n, t):
    polys = [[secrets.randbelow(q) for _ in range(t + 1)] for _ in range(n)]
    commitments = [commit(poly) for poly in polys]

    # s_{i,j} = f_i(j): deo koji učesnik i šalje učesniku j
    shares = [[eval_poly(polys[i], j) for j in range(1, n + 1)]
              for i in range(n)]
    for i in range(n):
        for j in range(1, n + 1):
            assert verify((j, shares[i][j - 1]), commitments[i])

    # deo zajedničke tajne učesnika j: s_j = sum_i s_{i,j}
    final = [(j, sum(shares[i][j - 1] for i in range(n)) % q)
             for j in range(1, n + 1)]

    # zajednički javni ključ: A = g^s = prod_i C_{i,0}
    A = 1
    for C in commitments:
        A = (A * C[0]) % p
    return final, A
~~~

Moderne varijante ovog protokola imaju dodatna ojačanja. Na primer, pored
obavezivanja, učesnik \\(i\\) objavljuje Šnorov dokaz sa nula znanja za tajnu
vrednost \\(a _{i, 0}\\) i svaki učesnik proverava Šnorov dokaz svakog drugog
učesnika. Ovakvo proširenje protokola sprečava napad koji napadaču omogućava
da namesti tajnu vrednost \\(s\\) izborom lažne obaveze \\(C _{i, 0} = g^s
C^{-1}\\) gde je \\(C = \prod _{j \neq i} C _{j, 0} \\).

~~~python
def prove_knowledge(a):
    C = pow(g, a, p)
    k = secrets.randbelow(q - 1) + 1
    K = pow(g, k, p)
    e = int.from_bytes(hash_obj((C, K)), "big") % q
    return K, (k + e * a) % q

def verify_knowledge(C, proof):
    K, z = proof
    e = int.from_bytes(hash_obj((C, K)), "big") % q
    return pow(g, z, p) == (K * pow(C, e, p)) % p
~~~

## ElGamal enkripcija

Deljenu tajnu je moguće koristiti kao privatni ključ za ElGamal enkripciju. U
slučaju Šamirovog ili Feldmanovog deljenja tajne, gde postoji centralni
delilac, on objavljuje javni ključ \\(g^s\\) koji se koristi za šifrovanje
poruka. U slučaju Pedersenovog protokola, javni ključ se računa kao \\(g^s =
\prod _{i=1}^n C _{i, 0}\\).

Šiforvanje se vrši na standardni način tako da se dobije šifrat \\((R, c)\\)
gde je \\(R=g^r\\), \\(c = km\\) i \\(k = g^{rs}\\). Dešifrovanje zahteva
\\(t+1\\) učesnika. Svaki učesnik \\(i\\) računa \\(k_i = R^{s_i}\\) gde je
\\(s_i\\) njegov deo tajne, pa kako je \\(s = f(0) = s_1 l_1(0) + \dots +
s_{t+1} l_{t+1}(0)\\), važiće \\(k = R^s = \prod_i k_i^{l_i(0)}\\). Tada je
poruku moguće dešifrovati kao \\(m = k^{-1}c\\). Primetimo da na ovaj način
nije direktno rekonstruisana tajna vrednost \\(s\\).

~~~python
def encrypt(m, A):
    r = secrets.randbelow(q - 1) + 1
    R = pow(g, r, p)
    k = pow(A, r, p)
    return R, (k * m) % p

def partial_decrypt(R, s_i):
    return pow(R, s_i, p)

def combine(R, c, partials):
    coeffs = lagrange(list(partials))
    k = 1
    for i, k_i in partials.items():
        k = (k * pow(k_i, coeffs[i], p)) % p
    return (c * pow(k, -1, p)) % p
~~~

## Šnorov potpis

Ključevi za Šnorov potpis sa deljenom tajnom se generišu na isti način kao i
kod ElGamal enkripcije. Potpisivanje zahteva \\(t+1\\) učesnika se vrši na
sledeći način. Svaki učesnik \\(i\\) bira slučajan broj \\(r_i\\) i računa
\\(R_i = g^{r_i}\\). Na osnovu ovoga se računa zajedničko \\(R = \prod_i R_i =
g^r\\) gde je \\(r = \sum_i r_i\\). Određuje se jedan zajednični izazov \\(c =
h(R, m)\\) i svaki učesnik računa svoj deo potpisa \\(p_i = r_i + c l_i(0)
s_i\\). Konačni potpis je \\(p = \sum_i p_i = \sum_i r_i + c \sum_i l_i(0) s_i
= r + c s\\). Provera potpisa se vrši na standardni način.

~~~python
def challenge(R, m):
    return int.from_bytes(hash_obj((R, m)), "big") % q

def sign(m, shares):
    signers = list(shares)
    rs = {i: secrets.randbelow(q - 1) + 1 for i in signers}
    R = 1
    for i in signers:
        R = (R * pow(g, rs[i], p)) % p
    c = challenge(R, m)
    coeffs = lagrange(signers)
    parts = {i: (rs[i] + c * coeffs[i] * shares[i]) % q for i in signers}
    return R, sum(parts.values()) % q

def verify(m, R, P, A):
    c = challenge(R, m)
    return pow(g, P, p) == (R * pow(A, c, p)) % p
~~~


## Zadaci

U zadacima sa konkretnim brojevima (2 i 7) koristi se ciklična podgrupa reda
\\(q\\) grupe \\(\mathbb{Z}_p^*\\) sa generatorom \\(g\\):

~~~python
p = 1267650600228229401496703217287
q = 633825300114114700748351608643
g = 2
~~~

### Zadatak 1

Implementirati server koji generiše delove tajne Šamirovim protokolom tako da
je za rekonstrukciju potrebno \\(3\\) od \\(5\\) delova. Pritom, server treba
da sabotira učesnika 2, odnosno bilo koji skup od tri učesnika koji uključuje
učesnika 2 treba da prilikom rekonstrukcije dobije pogrešnu tajnu vrednost.

### Zadatak 2

Grupa od \\(n\\) učesnika generiše zajednički javni ključ tako što svaki
učesnik \\(i\\) objavljuje doprinos \\(C_i = g^{a_i}\\), a zajednički ključ se
računa kao \\(A = \prod_i C_i\\). Ako su poznati doprinosi svih prethodnih učesnika,
namestiti doprinos poslednjeg učesnika tako da odgovarajući zajednički tajni
ključ bude \\(x = 1337\\).

~~~python
others = [526504585288905119860786968747, 751429976279136810775446160289,
          1174038313191067889758460100673, 646711060212620438228628540866]
~~~

### Zadatak 3

Predložiti način da se napad iz zadatka 2 spreči.

### Zadatak 4

Opisati i implementirati postupak kojim је moguće osvežiti delove tajne,
oslanjajući se na deljenje vrednosti \\(0\\). Potrebno je izmeniti delove tajne
tako svi stari kompromitovani delovi tajne postanu neupotrebljivi, pod
pretpostavkom da je bilo najviše \\(t\\) kompromitovanih.

### Zadatak 5

Pri dešifrovanju ElGamal šifrata sa deljenom tajnom svaki učesnik \\(i\\)
objavljuje delimični dešifrat \\(k_i = R^{s_i}\\). Zlonameran učesnik može da
objavi pogrešnu vrednost i tako neprimetno pokvari rezultat dešifrovanja.
Opisati sigma protokol kojim učesnik dokazuje da je njegov delimični dešifrat
ispravan, odnosno da važi \\(\log_R k_i = \log_g A_i\\), gde je \\(A_i =
g^{s_i}\\) javno poznata vrednost. Transformisati protokol u neinteraktivan
dokaz pomoću Fiat–Šamir heuristike.

### Zadatak 6

Implementirati protokol u kome \\(n\\) servera Pedersenovim distribuiranim
generisanjem ključa uspostavlja zajednički javni ključ i objavljuje ga
klijentima. Klijent šalje poruku šifrovanu ElGamal enkripcijom, a serveri je
dešifruju jedino ako bar \\(t+1\\) njih sarađuje. Tajna vrednost \\(s\\) se pri
tome nikada ne rekonstruiše.

### Zadatak 7

Grupa učesnika koristi Šnorov potpis sa deljenom tajnom. Učesnik \\(i\\) je pri
dva potpisivanja iskoristio istu slučajnu vrednost \\(r_i\\), dok su ostali
učesnici koristili nove vrednosti. Poznati su delimični potpisi \\(p_i\\)
učesnika \\(i\\) iz oba potpisivanja, odgovarajući izazovi, kao i skup učesnika
koji potpisuju poruke. Odrediti deo tajne \\(s_i\\) učesnika \\(i\\).

~~~python
signers = [1, 3, 5]  # indeksi učesnika koji potpisuju poruke
i = 3                # učesnik koji je ponovio r_i
A_i = 1004631559607981823051483430116
c1, pi1 = 4812911075131955971163679542, 431509380094865034067600365151
c2, pi2 = 399861716824313323430540420606, 517878666659093061272355479587
~~~

### Zadatak 8

Implementirati protokol u kome \\(n\\) učesnika generiše zajednički javni ključ,
a zatim bilo kojih \\(t+1\\) učesnika može zajednički da proizvede Šnorov potpis
poruke. Potpis se proverava na standardni način u odnosu na zajednički javni
ključ.

## Rešenja

### Zadatak 3

TODO

### Zadatak 4

TODO

### Zadatak 5

TODO
