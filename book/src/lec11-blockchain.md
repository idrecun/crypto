# Primena kriptografije u blokčejnu

## Opis problema

> Dizajnirati sistem za vođenje evidencije o monetarnim transakcijama (npr. Ana
> šalje Bobanu 3000 dinara) koji ne zavisi ni od jednog centralnog autoriteta
> kome je neophodno verovati.

Blokčejn je distribuirani sistem koji omogućava da grupa međusobno
nepoverljivih učesnika vodi zajedničku evidenciju o izvršenim transakcijama.
Ukratko, *blokčejn mreža* je peer-to-peer mreža u kojoj svaki čvor održava svoj
lanac blokova, tj. *blokčejn*. Blok je struktura koja sadrži spisak
transakcija. Čvorovi u mreži se dogovaraju o tome koji lanac je ispravan, što
znači da pod normalnim okolnostima svi čvorovi vide isti lanac blokova.

## Blokčejn

### Blok i lanac blokova

Blok je struktura koja sadrži spisak izvršenih transakcija, kao i još neka
polja neophodna za funkcionisanje blokčejna. Jedno od tih polja je heš
prethodnog bloka (roditelja). Heš bloka se računa kao heš svih njegovih polja.
Postoje dve važne posledice ovoga. Prva je da je na ovaj način definisan
poredak (lanac) među blokovima. Druga je da za bilo koji lanac možemo da
proverimo da li je validan tako što redom proveravamo poklapanje heševa. Ako
postoji nepoklapanje, smatramo da je lanac neispravan i odbacujemo ga.

<!-- slika lanca sa hesevima -->

Ukoliko korisnik želi da mu transkacija bude uključena u blokčejn, šalje je
jednom od čvorova u mreži. Čvor dalje propagira transakciju ostatku mreže.
Svaki čvor održava spisak transakcija (*mempool*) koje još nisu uključene u
blokčejn. Kada čvor odluči da predloži novi blok mreži, upisuje transakcije iz
svog spiska u blok zajedno sa hešom poslednjeg bloka iz svog lanca i šalje
predlog bloka ostatku mreže. Mi ćemo u nastavku pretpostaviti da se umesto samo
novog bloka šalje ceo novi lanac jer to pojednostavljuje neke detalje. U
praksi, ako je nekom čvoru u mreži potreban deo lanca pored predloženog bloka,
on to može zatražiti od čvora koji je poslao predlog.

### Kopanje blokova i dokaz o radu

Potrebno je napraviti mehanizam koji omogućava mreži da se složi oko toga koji
od validnih lanaca je kanonski. Zbog ovoga se uvodi koncept "dokaza o radu".
Ideja je da predlaganje novog bloka bude u nekoj meri "skupa" operacija.
Definiše se težina rada \\(d\\) koja određuje sa koliko bitova nule mora da
počinje heš predloženog bloka. Primetimo da je, pod pretpostavkama
kriptografskih heš funkcija, jedin način da se ovakva heš vrednost efektivno
odredi korišćenjem brute-force pristupa. Jedno od polja u bloku je prirodan
broj `nonce` i čvor koji predlaže blok, nakon popunjavanja ostalih polja,
pokušava da namesti vrednost `nonce` polja tako da heš bloka ispunjava
prethodno pomenut uslov, redom pokušavajući vrednosti 0, 1, 2, itd. Očekivani
broj pokušaja je \\(2^d\\). Ovaj proces se naziva "kopanje" blokova.

Kanonski lanac se onda bira kao validan lanac sa najvećom ukupnom težinom, ili
ekvivalentno (ako je težina ista za svaki blok) kao najduži validan lanac. Sa
ovakvim pravilom, dokle god pošteni čvorovi zbirno poseduju većinu ukupne
računske snage u mreži, biće održan ispravan kanonski lanac.

Primetimo da se može desiti da dva čvora skoro istovremeno iskopaju različite
blokove. To znači da će različiti delovi mreže videti različite kanonske lance
u istom trenutku, ali ovo će se razrešiti samo od sebe kako se kopanje
nastavlja, jer će jedan od ta dva lanca ubrzo postati duži sa velikom
verovatnoćom. U tom slučaju, potrebno je transakcije koje su iskopane u
izgubljenom bloku vratiti u mempool. Ovakav događaj nazivamo reorganizacijom
blokčejna. Zbog ovakvih situacija, transakcija se smatra konačnom tek nakon što
je posle nje iskopan određen broj blokova.

<!-- slike: fork, reorg -->

Primetimo i da je promena istorije blokčejna veoma skupa operacija. Ako bi neko
želeo da promeni neki blok sto blokova unazad, morao bi ponovo da iskopa svih
narednih sto blokova i da pretekne trenutni najduži lanac. Zbog ovoga, blokčejn
je praktično nepromenljiv.

### Transakcije i stanje

Svaka blokčejn mreža ima svoju fiktivnu valutu. Svaki čvor održava trenutno
stanje koje oslikava koliko koji korisnik ima novca, a koje je posledica
izvršavanja svih transakcija sa svih blokova od početka do kraja lanca.
Korisnik se poistovećuje sa svojim javnim ključem, a stanje se vodi po adresama
koje su izvedene iz javnih ključeva.

Jedan pristup održavanju stanja je da se vodi evidencija o računu svakog
korisnika, odnosno da se održava mapiranje iz adrese u vrednost izraženu u
valuti blokčejna (ovo je npr. pristup koji koristi Ethereum).

<!-- slika -->

U nastavku teksta ćemo se fokusirati na drugi pristup (koji koristi Bitcoin).
Ovaj pristup održava skup nepotrošenih izlaza transakcija (eng. *unspent
transaction outputs*, UTXO). Transakcija ima skup ulaza (nepotrošenih izlaza iz
prethodnih transakcija) i skup novih izlaza, pri čemu svaki izlaz ima adresu i
iznos. Na primer, ako korisnik A ima dva nepotrošena izlaza sa iznosima 10 i
20, a želi da izvede prenos u iznosu od 25 korisniku B, on troši oba svoja
izlaza i kreira dva nova izlaza, jedan za korisnika B sa iznosom 25 i jedan za
sebe sa kusurom u iznosu 5.

<!-- slika -->

Transakcija je validna ako su svi njeni ulazi validni (postoje u skupu
nepotrošenih izlaza) i ako je zbir iznosa ulaza jednak zbiru iznosa izlaza.
Takođe, neophodno je da uz svaki ulaz bude priložen i potpis heša svih ulaza i
izlaza transakcije, koji odgovara njegovom javnom ključu.

~~~python
def make_transaction(inputs, outputs, keys):
    message = h(inputs, outputs)
    signatures = [ecdsa.sign(message, key) for key in keys]
    return {"inputs": inputs, "outputs": outputs, "signatures": signatures}
~~~

Primetimo da je neophodno da poruka koju potpisujemo obuhvati i izlaze, jer bi
u suprotnom napadač mogao da vidi tuđu potpisanu transakciju koja još uvek nije
uključena u blokčejn, iskopira potpisane ulaze i podnese novu transakciju koja
preusmerava novac sa tih ulaza sebi.

### Merkle stablo

Blok obično sadrži više transakcija, a u zaglavlju želimo jednu kratku vrednost
koja se obavezuje na sve njih, tako da heš zaglavlja jednoznačno određuje ceo
skup transakcija. Pri tome bi bilo korisno da „laki” klijent, koji ne čuva ceo
lanac, može da proveri da je određena transakcija u bloku, a da ne preuzima sve
ostale. Oba zahteva ispunjava *Merkle stablo*, sa kojim smo se već sreli uz
Lamportov potpis u desetom poglavlju.

Merkle stablo gradimo tako što transakcije (njihove heševe) postavimo kao listove,
pa zatim parove čvorova spajamo heširanjem dok ne ostane jedan čvor — *koren*. Ako
je broj čvorova na nekom nivou neparan, poslednji čvor dupliramo.

~~~python
def merkle_root(leaves):
    level = [h(leaf) for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [h(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]
~~~

Da bismo dokazali da se neki list nalazi u stablu, dovoljno je priložiti susede
duž putanje od lista do korena. Proveravač tom putanjom ponovo izračunava
heševe naviše i upoređuje rezultat sa korenom. Veličina ovog dokaza je
logaritamska u odnosu na broj transakcija.

~~~python
def verify_proof(root, leaf, path):
    node = h(leaf)
    for sibling, right in path:
        node = h(sibling, node) if right else h(node, sibling)
    return node == root
~~~

Primetimo da dupliranje poslednjeg čvora nije bezazleno: liste transakcija
\\([A, B, C]\\) i \\([A, B, C, C]\\) daju isti koren. Ovo je bila stvarna ranjivost
u Bitkoinu (CVE-2012-2459) i pokazuje da i naizgled sporedne odluke u konstrukciji
mogu imati bezbednosne posledice. U praksi se zato fiksira broj transakcija i
domenski razdvajaju heševi listova i unutrašnjih čvorova.

Time je transparentni blokčejn zaokružen: imamo lanac blokova povezan dokazom
rada, mrežu koja se slaže oko najdužeg lanca, i transakcije čije vlasništvo
štite digitalni potpisi. Sve je, međutim, potpuno javno.

## Anonimnost

Na prethodno opisanim javnim lancima (npr. Bitcoin, Ethereum) sve transakcije
su javno dostupne i poznate čitavoj mreži, uključujući i iznose i adrese
pošiljalaca i primalaca. U nastavku ćemo opisati jedan pristup (koji koristi
Monero) koji omogućava sakrivanje svih ovih informacija.

Napomenimo da 

### Skrivene adrese

Prikažimo prvo način kojim možemo sakriti primaoca u transakciji. Ideja je da
se umesto direktnog transfera novca na adresu primaoca koriste jednokratne,
skrivene (eng. stealth) adrese.

Pretpostavimo da je \\(G\\) generator ciklične grupe nad kojom su generisani
parovi ključeva (koristimo notaciju kao u slučaju eliptičkih krivih). Neka je
javni ključ primaoca \\(B = bG\\). Pošiljalac bira slučajno \\(r\\), objavljuje
\\(R = rG\\) i računa jednokratnu Difi-Helman tajnu \\(s = h(rB)\\) (gde je
\\(h\\) heš funkcija). Jednokratni javni ključ izlaza je \\(P = sG + B\\).
Primalac računa Difi-Helman tajnu kao \\(s = h(bR)\\) i računa jednokratni
tajni ključ \\(p = s + b\\). Proverava da li je \\(P = pG\\) i ako jeste zna da
je on primalac. Primetimo da bez poznavanja originalnog privatnog ključa
\\(b\\) nije moguće odrediti \\(p\\) i nije moguće povezati javni ključ \\(P\\)
sa javnim ključem \\(B\\).

### Prstenasti potpis

Razmotrimo sada na koji način je moguće sakriti pošiljaoca u transakciji.
Umesto potpisivanja jednog ulaza, pošiljalac potpisuje

Trošenje izlaza zahteva potpis odgovarajućim privatnim ključem, ali običan
potpis otkriva tačno koji se izlaz troši. Potrebna nam je mogućnost da dokažemo
„poznajem privatni ključ za *jedan* od ovih izlaza”, bez otkrivanja za koji. To
je *prstenasti potpis*.

Podsetimo se Šnorovog dokaza poznavanja diskretnog logaritma iz osmog poglavlja:
da bismo dokazali da znamo \\(x\\) za \\(P = xG\\), biramo slučajno \\(a\\),
šaljemo \\(L = aG\\), dobijamo izazov \\(c\\) i odgovaramo sa \\(s = a - cx\\);
proveravač prihvata ako je \\(L = sG + cP\\). Fiat–Šamir heuristikom izazov
računamo kao heš, pa dokaz postaje neinteraktivan.

Prsten od \\(n\\) javnih ključeva \\(P_0, \dots, P_{n-1}\\), od kojih za jedan
(na tajnom indeksu \\(\pi\\)) znamo privatni ključ, obrađujemo kao
*ILI-dokaz*: za prave članove *znamo* tajnu, a za ostale *simuliramo* dokaz
biranjem slučajnih odgovora unapred. Izazove vezujemo u prsten tako što izazov
svakog člana zavisi od prethodnog, a ceo prsten „zatvaramo” baš na pravom
indeksu, koristeći poznatu tajnu.

~~~python
def sign(m, ring, x, pi):
    r = len(ring)
    s = [random_scalar() for _ in ring]
    c = [0] * r
    a = random_scalar()
    L = ec.mul(a, G)
    c[(pi + 1) % r] = challenge(m, ring, L)          # izazov sledećeg člana
    for k in range(1, r):                            # simuliraj ostale članove
        i = (pi + k) % r
        L = ec.add(ec.mul(s[i], G), ec.mul(c[i], ring[i]))
        c[(i + 1) % r] = challenge(m, ring, L)
    s[pi] = (a - c[pi] * x) % n                       # zatvori prsten (n = red grupe)
    return c[0], s

def verify(m, ring, signature):
    c0, s = signature
    c = c0
    for i in range(len(ring)):
        L = ec.add(ec.mul(s[i], G), ec.mul(c, ring[i]))
        c = challenge(m, ring, L)
    return c == c0                                     # lanac se zatvorio
~~~

Ostaje pitanje dvostruke potrošnje: pošto se ne zna koji je izlaz potrošen, ne
možemo ga jednostavno obeležiti kao potrošen. Rešenje je *slika ključa* (engl.
_key image_): uz potpis objavljujemo vrednost \\(I = x H_p(P)\\), gde je \\(H_p\\)
heš u tačku krive, a \\(x\\) privatni ključ koji se troši.

~~~python
def key_image(x, P):
    return ec.mul(x, hash_to_point(P))
~~~

Slika ključa je deterministička funkcija privatnog ključa, pa dva potpisa istim
ključem daju istu sliku ključa — čvorovi prosto pamte skup viđenih slika i
odbijaju ponovljene. Pri tome \\(I\\) ne otkriva *koji* je izlaz potrošen.
Da bi slika ključa bila verodostojna, potpisnik mora i da dokaže da je \\(I\\)
ispravno sačinjeno, odnosno da isti \\(x\\) povezuje \\(P = xG\\) i \\(I = xH_p(P)\\)
— a to je upravo dokaz jednakosti diskretnih logaritama iz devetog poglavlja.
Zato se prstenasti potpis proširuje tako da svaki član nosi i ovaj dodatni
sloj; takvu povezivu varijantu objavio je Monero pod imenom LSAG.

### Poverljivi iznosi

Najzad sakrivamo iznos. Umesto da iznos stoji otvoreno, izlaz nosi *Pedersenovu
obavezu* iz osmog poglavlja, \\(C = vG + bH\\), gde je \\(v\\) iznos, \\(b\\)
slučajan zaslepljujući faktor, a \\(H\\) drugi generator čiji diskretni logaritam
u odnosu na \\(G\\) niko ne zna. Obaveza ne otkriva \\(v\\), ali se i dalje može
proveriti ravnoteža transakcije, zahvaljujući homomorfizmu obaveza:

~~~python
def commit(v, b):
    return ec.add(ec.mul(v, G), ec.mul(b, H))
~~~

Naime, zbog homomorfizma je zbir obaveza \\(\sum_k C_k = (\sum_k v_k) G + (\sum_k
b_k) H\\). Ako pošiljalac izabere zaslepljujuće faktore tako da im je zbir na
ulazima jednak zbiru na izlazima, onda je razlika zbira obaveza ulaza i izlaza
jednaka neutralnoj tački \\(\mathcal{O}\\) tačno kada je i zbir ulaznih iznosa
jednak zbiru izlaznih. Čvor, dakle, proverava da je ta razlika jednaka
\\(\mathcal{O}\\), ne saznavši pri tom nijedan iznos.

Ravnoteža sama po sebi nije dovoljna. Pošto se sve računa po modulu reda grupe,
„negativan” iznos (velika vrednost koja se prelije) može lažno da zatvori bilans
i tako *iskuje* novac. Zato uz svaki izlaz mora ići i *dokaz opsega* (engl.
_range proof_), koji potvrđuje da je sakriveni iznos u dozvoljenom opsegu
\\([0, 2^k)\\), bez otkrivanja same vrednosti. Dokaze opsega koji se koriste u
praksi (Bulletproofs) ne izlažemo — koristimo ih kao gotovu primitivu, slično
kao što smo u desetom poglavlju koristili dokaze sa nula znanja kao crnu kutiju.

### Spajanje: RingCT

Sakrivanje iznosa i prstenasti potpis u naizgled su u sukobu. Provera ravnoteže
zahteva da znamo obaveze potrošenih ulaza — ali prsten upravo krije koji su to
ulazi. Rešenje je da se dokaz ravnoteže *stopi* sa prstenastim potpisom.

Pošiljalac za svaki ulaz objavljuje *pseudo-obavezu* \\(C'\\) na isti iznos kao
stvarni ulaz, ali sa novim zaslepljujućim faktorom, i bira faktore tako da je
zbir pseudo-obaveza ulaza jednak zbiru obaveza izlaza. Time se ravnoteža
proverava nad pseudo-obavezama, bez otkrivanja koji su ulazi pravi. Da pseudo-
obaveza ne bi lažirala iznos, prsten se proširuje dodatnim slojem: za svakog
člana \\(i\\) posmatramo tačku \\(C_i - C'\\). Na pravom indeksu \\(\pi\\) važi
\\(C_\pi - C' = (b_\pi - b')H\\), dakle obaveza na *nulu* u vrednosti, čiji
diskretni logaritam u odnosu na \\(H\\) pošiljalac zna; za lažne članove to nije
slučaj. Potpisnik tako, na istom skrivenom indeksu, istovremeno dokazuje
poznavanje privatnog ključa izlaza i da pseudo-obaveza krije isti iznos kao
stvarni ulaz.

Ovakav višeslojni povezivi prstenasti potpis Monero naziva MLSAG. On objedinjuje
sve što smo izgradili: stealth adresa sakriva primaoca, prsten sakriva
pošiljaoca, a obaveze uz dokaze opsega sakrivaju iznos — uz sliku ključa koja i
dalje sprečava dvostruku potrošnju. Puna konstrukcija data je u pratećem kodu;
ovde smo, kao i ranije kod složenijih protokola, izložili samo glavnu ideju.

## Drugi pristupi

Sistem koji smo izgradili odgovara Moneru: privatnost počiva na stealth adresama,
prstenastim potpisima i obavezama, a gotovo svaki deo izveden je iz primitiva
ovog kursa — jedina prava crna kutija je dokaz opsega.

Postoji i bitno drugačiji pristup, koji koristi Zcash. Umesto prstena, svi
skriveni izlazi se kao obaveze smeštaju u jedno veliko Merkle stablo. Da bi
potrošio izlaz, korisnik dokazom sa nula znanja (poput onih iz desetog poglavlja)
dokazuje „znam otvaranje neke obaveze u ovom stablu i njen *poništavač* je baš
\\(N\\)”, ne otkrivajući o kojoj obavezi je reč. Poništavač (engl. _nullifier_)
igra istu ulogu kao slika ključa — sprečava dvostruku potrošnju — a Merkle stablo,
koje smo uveli radi lakih klijenata, ovde postaje skup svih mogućih lažnjaka,
odnosno ceo anonimni skup. Cena je oslanjanje na opštije (i složenije) dokaze sa
nula znanja, ali se zauzvrat dobija veći anonimni skup i sažetiji dokazi.

Oba pristupa pokazuju istu pouku: privatnost na javnom lancu ne dobija se jednom
primitivom, već pažljivim slaganjem više njih — heširanja, potpisa, razmene
ključeva, obavezivanja i dokaza sa nula znanja — od kojih smo većinu već sreli u
prethodnim poglavljima.
