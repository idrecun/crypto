import shamir
from shamir import g, p, q
from kurs import hash_obj


def challenge(R, m):
    return int.from_bytes(hash_obj((R, m)), "big") % q


def sign(m, shares):
    """Potpisivanje sa deljenom tajnom. shares je rečnik {i: s_i} potpisnika
    (bar t+1 njih). Svaki potpisnik bira slučajno r_i; zajedničko R = prod_i R_i.
    """
    signers = list(shares)
    rs = {i: shamir.rand_scalar() for i in signers}
    R = 1
    for i in signers:
        R = (R * pow(g, rs[i], p)) % p
    c = challenge(R, m)
    coeffs = shamir.lagrange(signers)
    # Delimični potpis učesnika i: p_i = r_i + c l_i(0) s_i.
    parts = {i: (rs[i] + c * coeffs[i] * shares[i]) % q for i in signers}
    P = sum(parts.values()) % q
    return R, P


def verify(m, R, P, A):
    c = challenge(R, m)
    return pow(g, P, p) == (R * pow(A, c, p)) % p


if __name__ == "__main__":
    s = 987654321
    A = pow(g, s, p)
    parts = dict(shamir.share(s, t=2, n=5))

    m = b"matf kripto"
    grupa = {1: parts[1], 3: parts[3], 5: parts[5]}
    R, P = sign(m, grupa)
    print(f"validan potpis: {verify(m, R, P, A)}")
    print(f"potpis za drugu poruku: {verify(b'druga poruka', R, P, A)}")
