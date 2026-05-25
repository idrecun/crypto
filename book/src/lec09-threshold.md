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

## Feldmanovo deljenje tajne

> Boban je izglasan da odabere i podeli tajni ključ grupi od pet ljudi.
> Potrebno je podeliti ključ na pet delova, tako da je moguće rekonstruisati ga
> na osnovu bilo koja tri dela, a da jedan ili dva dela ne otkrivaju ništa o
> tajnom ključu. Takođe, učesnici žele da mogu da provere da im Boban nije
> poslao nevažeće delove na osnovu kojih nije moguće rekonstruisati smislen
> ključ.

Feldmanovo deljenje tajne omogućava da svaki učesnik proveri da li je njegov
deo validan. Tajni polinom se konstruiše na isti način kao u Šamirovom deljenju
tajne, pri čemu se dodatno objavljuju obaveze koeficijenata polinoma. Ako je
polinom \\(f(x) = ax^2 + bx + c\\) u grupi \\(\mathbb{Z}_p\\), onda se
objavljuju obaveze \\(C_a = g^a, C_b = g^b, C_c = g^c\\) u nekoj grupi \\(G\\)
generisanoj elementom \\(g\\) reda \\(p\\). Učesnik koji je dobio deo \\((i,
s_i)\\) proverava da li je zaista \\(s_i = f(i)\\), odnosno da li je \\(s_i =
ai^2+bi+c\\) tako što proveri da li važi \\(g^{s_i} = C_a^{i^2} C_b^i C_c\\).
Primetimo da smo ovde koristili svojstvo homomorfizma obaveza, slično kao kod
Pedersenovog obavezivanja.

~~~python
~~~

## Pedersenovo distribuirano generisanje ključa

> Grupa od pet ljudi želi da generiše zajednički tajni ključ koji je moguće
> otkriti ukoliko se većina složi da to treba uraditi. Na koji način je to
> moguće uraditi?



## ElGamal

## Šnor

## Zadaci
