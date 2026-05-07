from pohlig_hellman import pohlig_hellman, dlp_naive

g = 3
p = 1870481974960029238219966388771406118351
B = 497191599874828811421853470900833470993
C = 1473663585592763770030583068836711465092
A = 1343596286854575049094069011811221332574


def brute_force():
    a = dlp_naive(g, A, p - 1, p)
    S = pow(B, a, p)
    return (C * pow(S, -1, p)) % p


def solve():
    a = pohlig_hellman(g, A, p)
    S = pow(B, a, p)
    return (C * pow(S, -1, p)) % p


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "brute":
        print(brute_force())
    else:
        M = solve()
        print(f"M = {M}")
        print(f"M (bytes) = {M.to_bytes((M.bit_length() + 7) // 8, 'big')}")
