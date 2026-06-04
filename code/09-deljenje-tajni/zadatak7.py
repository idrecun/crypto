p = 1267650600228229401496703217287
q = 633825300114114700748351608643
g = 2

# Učesnik i je u dva potpisivanja iskoristio isto r_i; izazovi c1 i c2 se
# razlikuju jer se zajedničko R razlikuje (iz gen_zadaci.py).
signers, i = [1, 3, 5], 3
A_i = 1004631559607981823051483430116
c1 = 4812911075131955971163679542
pi1 = 431509380094865034067600365151
c2 = 399861716824313323430540420606
pi2 = 517878666659093061272355479587

# Lagranžov koeficijent l_i(0) za dati skup potpisnika.
num, den = 1, 1
for j in signers:
    if j != i:
        num = (num * (-j)) % q
        den = (den * (i - j)) % q
li = (num * pow(den, -1, q)) % q

# pi1 = r_i + c1 l_i(0) s_i,  pi2 = r_i + c2 l_i(0) s_i
#   =>  s_i = (pi1 - pi2) / ((c1 - c2) l_i(0)) (mod q)
s_i = ((pi1 - pi2) * pow((c1 - c2) * li % q, -1, q)) % q
print(f"deo tajne s_i = {s_i}")
print(f"ispravno (g^s_i == A_i): {pow(g, s_i, p) == A_i}")
