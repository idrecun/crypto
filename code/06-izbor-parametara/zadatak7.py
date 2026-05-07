from miller_rabin import miller_rabin
from pollard_p1 import sieve


# Provera da li je p bezbedan izbor: p mora biti prost i p - 1 mora imati
# bar jedan prosti faktor veci od B.
def is_safe(p, B=1 << 16, k=40):
    if not miller_rabin(p, k):
        return False
    n = p - 1
    for q in sieve(B):
        while n % q == 0:
            n //= q
    return n > B


candidates = {
    "A": 230914455703691489588482744432827805051,
    "B": 1100412499263221912937307421102321256919,
    "C": 275314703551481333360766958972593260039,
    "D": 293720665814433582927735487060431957427,
}

for name, p in candidates.items():
    print(f"{name}: {'bezbedno' if is_safe(p) else 'nije bezbedno'}")
