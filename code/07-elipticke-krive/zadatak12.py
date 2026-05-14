# Provera da li je broj prost (probnim deljenjem - dovoljno za male n).
def is_prime(n):
    if n < 2:
        return False
    d = 2
    while d * d <= n:
        if n % d == 0:
            return False
        d += 1
    return True


# Naivno prebrojavanje tacaka na krivoj y^2 = x^3 + ax + b mod p.
def order(p, a, b):
    if (4 * a * a * a + 27 * b * b) % p == 0:
        return None  # kriva je degenerisana
    count = 1  # tacka u beskonacnosti
    for x in range(p):
        rhs = (x * x * x + a * x + b) % p
        if rhs == 0:
            count += 1
        elif pow(rhs, (p - 1) // 2, p) == 1:
            count += 2
    return count


# Bezbedna kriva: prost red grupe (otporno na Polig-Helmana).
def is_safe(p, a, b):
    n = order(p, a, b)
    return n is not None and is_prime(n)


candidates = {
    "1": (501367, 183559, 261029),
    "2": (1015009, 264169, 456192),
    "3": (1606901, 1519467, 586263),
    "4": (670487, 386126, 380490),
}

for name, (p, a, b) in candidates.items():
    n = order(p, a, b)
    print(f"{name}: red = {n}, {'bezbedno' if is_safe(p, a, b) else 'nije bezbedno'}")
