"""Verify all task values from lec07 by solving each attack."""
import hashlib
from sympy import factorint

# secp128r1
P = 340282366762482138434845932244680310783
A_PARAM = 340282366762482138434845932244680310780
B_PARAM = 308990863222245658030922601041482374867
N = 340282366762482138443322565580356624661
G = (29408993404948928992877151431649155974, 275621562871047521857442314737465260675)


def add(p1, p2, a=A_PARAM, p=P):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % p == 0: return None
        s = ((3*x1*x1 + a) * pow(2*y1, -1, p)) % p
    else:
        s = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (s*s - x1 - x2) % p
    y3 = (s*(x1 - x3) - y1) % p
    return (x3, y3)


def neg(P_, p=P):
    if P_ is None: return None
    return (P_[0], (-P_[1]) % p)


def mul(k, P_, a=A_PARAM, p=P):
    if P_ is None or k == 0: return None
    if k < 0: return mul(-k, neg(P_, p), a, p)
    R = None; Q = P_
    while k > 0:
        if k & 1: R = add(R, Q, a, p)
        Q = add(Q, Q, a, p)
        k >>= 1
    return R


def H(s):
    return int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % N


# ===== Task 5 =====
A5 = (38908903211101888278623563709835614940, 86414223312395224141852774166062813584)
B5 = (210067491220345722062217915833545932319, 314595414076388517941891137742153277344)
e5 = 99327691616788894527576870712013829048
print("Task 5 K_alice:", mul(e5, A5))
print("Task 5 K_bob  :", mul(e5, B5))

# ===== Task 6 =====
A6 = (172555618972274937527774535265768735313, 10081883194550683330255804375487986898)
M1 = (258195427694994240236789828875940887457, 337184816232937204958887835705857507231)
R1 = (70317932819526710602903815804549240940, 36813546415559138349030471247361636124)
C1 = (287066134838516450567688517941084959058, 218063401705308332321934229482059355773)
R2 = (70317932819526710602903815804549240940, 36813546415559138349030471247361636124)
C2 = (33302374266159024897512879673930207502, 336771186098399155523098592439895884956)
# M2 = C2 - C1 + M1 (since C-rA = M, so M2 - M1 = C2 - C1)
M2 = add(add(C2, neg(C1)), M1)
print("Task 6 M' =", M2)

# ===== Task 7 (EC-ElGamal sig nonce reuse) =====
A7 = (1446342285746087496322261997989149864, 51899882338286411277127986568238557735)
m1_7 = "Hello, world!"; m2_7 = "Hello, matf!"
R7 = (91407655570239612505893793489075498927, 25538088875613710856623369771771322160)
s1_7 = 311396362683851534909632246027045848057
s2_7 = 32731572252507648075677496446020975539
phi_R7 = R7[0] % N
# r*s1 = h1 - a*phi(R), r*s2 = h2 - a*phi(R)
# r*(s1-s2) = h1-h2 -> r = (h1-h2)/(s1-s2)
# a = (h1 - r*s1)/phi(R)
r7_rec = ((H(m1_7) - H(m2_7)) * pow((s1_7 - s2_7) % N, -1, N)) % N
a7_rec = ((H(m1_7) - r7_rec * s1_7) * pow(phi_R7, -1, N)) % N
print("Task 7 a =", a7_rec)
assert mul(a7_rec, G) == A7, "Task 7 verify failed"

# ===== Task 8 (EC-Schnorr nonce reuse) =====
A8 = (109467063707252142941786888194056392558, 283624804562688076124413520142906544564)
R8 = (69191772370633742414484574291592789683, 150081736994045835000962439583877754103)
m1_8 = "Zdravo, svete!"; m2_8 = "Vozdra, svete!"
s1_8 = 275532418724142788316051765718430826437
s2_8 = 22127400428374188013866090255927965142
def Hch(R, m):
    s = f"({R[0]},{R[1]})" + m
    return int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % N
c1_8 = Hch(R8, m1_8); c2_8 = Hch(R8, m2_8)
a8_rec = ((s1_8 - s2_8) * pow((c1_8 - c2_8) % N, -1, N)) % N
print("Task 8 a =", a8_rec)
assert mul(a8_rec, G) == A8, "Task 8 verify failed"

# ===== Task 9 (forge) =====
A9 = (246691936285505052706352817197487175489, 10886859581935478975083534919891668598)
m9 = "Vozdra, svete!"
def Hm(m):
    return int.from_bytes(hashlib.sha256(m.encode()).digest(), "big") % N
c9 = Hm(m9)
s9 = 12345678901234567890  # arbitrary
R9 = add(mul(s9, G), neg(mul(c9, A9)))
# verify: s*G == R + c*A
assert mul(s9, G) == add(R9, mul(c9, A9))
print(f"Task 9 forge OK: R={R9}, s={s9}")

# ===== Task 11 (Pohlig-Hellman) =====
p11 = 1940158473524142299
A11_param, B11_param = 0, 1
n11 = 1940158473524142300
G11 = (17, 213329057279393933)
A11 = (1057509392935454215, 1290626223251531797)

def bsgs(g, h, n, a, p):
    """Solve g^x = h in subgroup of order n; small n only."""
    m = int(n**0.5) + 1
    table = {}
    P_ = None
    for j in range(m):
        if P_ in table: pass
        table[P_] = j
        P_ = add(P_, g, a, p)
    # factor = m * g^{-1}
    inv_gm = neg(mul(m, g, a, p), p)
    Q = h
    for i in range(m):
        if Q in table:
            return (i * m + table[Q]) % n
        Q = add(Q, inv_gm, a, p)
    return None

def crt(rs, ms):
    x = 0; M = 1
    for m in ms: M *= m
    for r, m in zip(rs, ms):
        Mi = M // m
        x += r * Mi * pow(Mi, -1, m)
    return x % M

# Pohlig-Hellman
factors = factorint(n11)
residues = []
moduli = []
for q, e in factors.items():
    qe = q ** e
    Gi = mul(n11 // qe, G11, A11_param, p11)
    Hi = mul(n11 // qe, A11, A11_param, p11)
    xi = bsgs(Gi, Hi, qe, A11_param, p11)
    residues.append(xi); moduli.append(qe)
a11_rec = crt(residues, moduli)
print("Task 11 a =", a11_rec)
assert mul(a11_rec, G11, A11_param, p11) == A11

# ===== Task 12 (orders) =====
def order_naive(p, a, b):
    count = 1
    for x in range(p):
        rhs = (x*x*x + a*x + b) % p
        if rhs == 0: count += 1
        elif pow(rhs, (p-1)//2, p) == 1: count += 2
    return count

curves12 = [
    (501367, 183559, 261029),
    (1015009, 264169, 456192),
    (1606901, 1519467, 586263),
    (670487, 386126, 380490),
]
for i, (p, a, b) in enumerate(curves12, 1):
    o = order_naive(p, a, b)
    f = factorint(o)
    safe = "SAFE" if (len(f) == 1 and list(f.values())[0] == 1) else "UNSAFE"
    print(f"Task 12 curve {i}: order={o} {dict(f)} -> {safe}")
