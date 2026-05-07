from pohlig_hellman import pohlig_hellman, dlp_naive

g = 2
p = 7601624022030852444912481695317914837957
A = 2211695542287328335118624827317758656022
B = 6182657336541579015064991427667254728726


def brute_force():
    a = dlp_naive(g, A, p - 1, p)
    return pow(B, a, p)


def solve():
    a = pohlig_hellman(g, A, p)
    return pow(B, a, p)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "brute":
        print(brute_force())
    else:
        S = solve()
        print(f"S = {S}")
