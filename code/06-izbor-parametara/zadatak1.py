from pollard_p1 import pollard_p1

n = 128012969945026248732835279448470961755200314723736138420211480647446338936601
e = 45003644880317641650549332948458540440828733125352288665595332773107626216631
C = 17804263439160944615212115660102150497899902713732968130942328933737091348102


def brute_force(n):
    d = 2
    while d * d <= n:
        if n % d == 0:
            return d
        d += 1
    return None


def solve():
    p = pollard_p1(n, 2, 1 << 20)
    q = n // p
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return pow(C, d, n)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "brute":
        print(brute_force(n))
    else:
        M = solve()
        print(f"M = {M}")
        print(f"M (bytes) = {M.to_bytes((M.bit_length() + 7) // 8, 'big')}")
