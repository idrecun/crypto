from kurs import ec_a, ec_b, ec_p


def on_curve(P, a=ec_a, b=ec_b, p=ec_p):
    if P is None:
        return True
    x, y = P
    return (y * y - x * x * x - a * x - b) % p == 0


def neg(P, p=ec_p):
    if P is None:
        return None
    return (P[0], (-P[1]) % p)


def add(P, Q, a=ec_a, p=ec_p):
    if P is None:
        return Q
    if Q is None:
        return P
    if P == neg(Q, p):
        return None
    x1, y1 = P
    x2, y2 = Q
    if x1 != x2:
        s = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    else:
        s = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)


def sub(P, Q, a=ec_a, p=ec_p):
    return add(P, neg(Q, p), a, p)


def mul(k, P, a=ec_a, p=ec_p):
    if P is None or k == 0:
        return None
    if k < 0:
        return mul(-k, neg(P, p), a, p)
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = add(R, Q, a, p)
        Q = add(Q, Q, a, p)
        k >>= 1
    return R
