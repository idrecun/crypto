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
~~~

Moderne varijante ovog protokola imaju dodatna ojačanja. Na primer, pored
obavezivanja, učesnik \\(i\\) objavljuje Šnorov dokaz sa nula znanja za tajnu
vrednost \\(a _{i, 0}\\) i svaki učesnik proverava Šnorov dokaz svakog drugog
učesnika. Ovakvo proširenje protokola sprečava napad koji napadaču omogućava
da namesti tajnu vrednost \\(s\\) izborom lažne obaveze \\(C _{i, 0} = g^s
C^{-1}\\) gde je \\(C = \prod _{j \neq i} C _{j, 0} \\).

~~~python
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
~~~


## Zadaci
