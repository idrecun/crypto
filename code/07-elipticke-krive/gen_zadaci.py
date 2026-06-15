import hashlib
import random as rnd
from sympy import isprime, factorint, randprime

# === Main curve: secp128r1 ===
P = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
A_PARAM = (P - 3) % P
B_PARAM = 0xE87579C11079F43DD824993C2CEE5ED3
N = 0xFFFFFFFE0000000075A30D1B9038A115
G = (0x161FF7528B899B2D0C28607CA52C5B86, 0xCF5AC8395BAFEB13C02DA292DDED7A83)


def add(p1, p2, a=A_PARAM, p=P):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        s = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        s = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)


def neg(P_, p=P):
    if P_ is None:
        return None
    return (P_[0], (-P_[1]) % p)


def mul(k, P_, a=A_PARAM, p=P):
    if P_ is None or k == 0:
        return None
    if k < 0:
        return mul(-k, neg(P_, p), a, p)
    R = None
    Q = P_
    while k > 0:
        if k & 1:
            R = add(R, Q, a, p)
        Q = add(Q, Q, a, p)
        k >>= 1
    return R


def on_curve(P_, a=A_PARAM, b=B_PARAM, p=P):
    if P_ is None:
        return True
    x, y = P_
    return (y * y - x * x * x - a * x - b) % p == 0


# Verify
assert mul(N, G) is None, "G order != N"
assert on_curve(G)
print("# secp128r1 OK")

rnd.seed(20260514)


def rand(n):
    return rnd.randrange(2, n)


def fmt(P_):
    if P_ is None:
        return "O"
    return f"({P_[0]}, {P_[1]})"


print("\n# === MAIN CURVE PARAMS (secp128r1) ===")
print(f"# p = {P}")
print(f"# a = {A_PARAM}")
print(f"# b = {B_PARAM}")
print(f"# n = {N}")
print(f"# G = {fmt(G)}")

# === Task 2: MITM ECDH ===
print("\n# === Task 2: MITM ECDH ===")
a5 = rand(N)
A5 = mul(a5, G)
b5 = rand(N)
B5 = mul(b5, G)
e5 = rand(N)
print(f"A = {fmt(A5)}")
print(f"B = {fmt(B5)}")
print(f"e = {e5}")
print(f"# K_alice = {fmt(mul(e5, A5))}")
print(f"# K_bob   = {fmt(mul(e5, B5))}")

# === Task 3: EC-ElGamal same R ===
print("\n# === Task 3: EC-ElGamal same R ===")
a6 = rand(N)
A6 = mul(a6, G)
r6 = rand(N)
R6 = mul(r6, G)
M1 = mul(rand(N), G)
M2 = mul(rand(N), G)  # the target
C1 = add(M1, mul(r6, A6))
C2 = add(M2, mul(r6, A6))
print(f"A = {fmt(A6)}")
print(f"M1 = {fmt(M1)}")
print(f"R1 = {fmt(R6)}")
print(f"C1 = {fmt(C1)}")
print(f"R2 = {fmt(R6)}")
print(f"C2 = {fmt(C2)}")
print(f"# M2 (private) = {fmt(M2)}")

# === Task 4: EC-ElGamal signature nonce reuse ===
print("\n# === Task 4: EC-ElGamal sig nonce reuse ===")


def H(s):
    return int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % N


a7 = rand(N)
A7 = mul(a7, G)
m1_7 = "Hello, world!"
m2_7 = "Hello, matf!"
r7 = rand(N)
R7 = mul(r7, G)
phi_R7 = R7[0] % N
s1_7 = (pow(r7, -1, N) * (H(m1_7) - a7 * phi_R7)) % N
s2_7 = (pow(r7, -1, N) * (H(m2_7) - a7 * phi_R7)) % N
print(f"A = {fmt(A7)}")
print(f"m1 = {m1_7!r}")
print(f"R1 = {fmt(R7)}")
print(f"s1 = {s1_7}")
print(f"m2 = {m2_7!r}")
print(f"R2 = {fmt(R7)}")
print(f"s2 = {s2_7}")
print(f"# a (private) = {a7}")

# === Task 5: EC-Schnorr nonce reuse ===
print("\n# === Task 5: EC-Schnorr nonce reuse ===")


def Hch(R, m):
    s = f"({R[0]},{R[1]})" + m
    return int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % N


a8 = rand(N)
A8 = mul(a8, G)
m1_8 = "Zdravo, svete!"
m2_8 = "Vozdra, svete!"
r8 = rand(N)
R8 = mul(r8, G)
c1_8 = Hch(R8, m1_8)
c2_8 = Hch(R8, m2_8)
s1_8 = (r8 + a8 * c1_8) % N
s2_8 = (r8 + a8 * c2_8) % N
print(f"A = {fmt(A8)}")
print(f"m1 = {m1_8!r}")
print(f"R1 = {fmt(R8)}")
print(f"s1 = {s1_8}")
print(f"m2 = {m2_8!r}")
print(f"R2 = {fmt(R8)}")
print(f"s2 = {s2_8}")
print(f"# a (private) = {a8}")

# === Task 6: EC-Schnorr without R in hash ===
print("\n# === Task 6: EC-Schnorr no R in hash ===")


def Hm(m):
    return int.from_bytes(hashlib.sha256(m.encode()).digest(), "big") % N


a9 = rand(N)
A9 = mul(a9, G)
print(f"A = {fmt(A9)}")
print(f"# a (private) = {a9}")

# === Task 8: Pohlig-Hellman on smooth-order curve ===
print("\n# === Task 8: Pohlig-Hellman ===")


def find_smooth_curve():
    sp = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    for _ in range(200000):
        n = 1
        while n < 2**60:
            n *= rnd.choice(sp)
        if n > 2**80:
            continue
        p = n - 1
        if p % 12 != 11:
            continue
        if isprime(p):
            return p, n
    return None


found = find_smooth_curve()
if found:
    p11, n11 = found
    a11_param, b11 = 0, 1
    # find a point on y^2 = x^3 + 1 mod p
    fac11 = factorint(n11)
    G11 = None
    for x in range(2, 10000):
        rhs = (x * x * x + 1) % p11
        y = pow(rhs, (p11 + 1) // 4, p11)
        if (y * y) % p11 != rhs:
            continue
        cand = (x, y)
        if mul(n11, cand, a11_param, p11) is not None:
            continue
        # ord(cand) = n11 iff (n11/q)*cand != O for every prime q | n11
        is_gen = True
        for q in fac11:
            if mul(n11 // q, cand, a11_param, p11) is None:
                is_gen = False
                break
        if is_gen:
            G11 = cand
            break
    assert G11 is not None
    a_priv11 = rnd.randrange(2, n11)
    A11 = mul(a_priv11, G11, a11_param, p11)
    assert A11 is not None
    print(f"p = {p11}")
    print(f"a = 0")
    print(f"b = 1")
    print(f"n = {n11}")
    print(f"# factor(n) = {factorint(n11)}")
    print(f"G = {fmt(G11)}")
    print(f"A = {fmt(A11)}")
    print(f"# a (private) = {a_priv11}")
