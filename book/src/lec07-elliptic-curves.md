# Eliptičke krive

## Definicija problema

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
~~~

### Izvođenje Vajerštrasove forme

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
~~~

### Množenje skalarom

Na osnovu sabiranja možemo jednostavno definisati množenje tačke prirodnim
brojem. Izveli smo formule za \\(2P = P + P\\). Jasno je da onda možemo
izračunati i \\(3P = 2P + P\\), \\(4P = 3P + P\\), itd. Ako bismo na ovaj način
računali \\(nP\\), složenost bi bila \\(O(n)\\). Umesto ovoga, možemo primeniti
isti algoritam kao za efikasno stepenovanje, čija je složenost \\(O(\log n)\\).

~~~python
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

## Protokoli zasnovani na eliptičkim krivama

Kao javni parametar bilo kog protokola potrebno je odabrati eliptičku krivu nad
nekim konačnim poljem. Biraju se parametri \\(p\\) (koji određuje konačno polje)

### Generisanje ključeva

Generisanje ključeva funkcioniše kao i u do sada opisanim protokolima zasnovanim na problemu diskretnog logaritma.

### Validacija javnog ključa

### Difi-Helman razmena ključa

### ElGamal enkripcija

### ElGamal potpis

### Šnorov potpis

## Zadaci
