from pollard_p1 import pollard_p1

n = 7603286354234243903435872704677498363399458016631578496018195845589487786172473
e = 7535918899271596912605330771330141519800214292622992808169830647334620913196679
M = 11111


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
    return pow(M, d, n)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "brute":
        print(brute_force(n))
    else:
        S = solve()
        print(f"S = {S}")
        print(f"provera: S^e mod n = {pow(S, e, n)}, M = {M}")
