from kurs import hash_obj

p = 1267650600228229401496703217287
q = 633825300114114700748351608643
g = 2

# Potpisi (R, p1) i (R, p2) dele isto zajedničko R (pojedinačne vrednosti r_i se
# razlikuju, ali im je zbir isti).
A = 566770316454856307829090272389
R = 48782703516910801051292529125
m1, m2 = b"Zdravo, svete!", b"Vozdra, svete!"
p1 = 451936851426871684204850359794
p2 = 175413685088376135148001806143


def challenge(R, m):
    return int.from_bytes(hash_obj((R, m)), "big") % q


c1, c2 = challenge(R, m1), challenge(R, m2)
# p1 = r + c1 s,  p2 = r + c2 s  =>  s = (p1 - p2) / (c1 - c2) (mod q)
s = ((p1 - p2) * pow(c1 - c2, -1, q)) % q
print(f"deljena tajna s = {s}")
print(f"ispravno (g^s == A): {pow(g, s, p) == A}")
