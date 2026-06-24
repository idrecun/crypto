ec_p = 340282366762482138434845932244680310783
ec_a = 340282366762482138434845932244680310780


def neg(P):
    if P is None:
        return None
    return (P[0], (-P[1]) % ec_p)


def add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P == neg(Q):
        return None
    x1, y1 = P
    x2, y2 = Q
    if x1 != x2:
        s = ((y2 - y1) * pow(x2 - x1, -1, ec_p)) % ec_p
    else:
        s = ((3 * x1 * x1 + ec_a) * pow(2 * y1, -1, ec_p)) % ec_p
    x3 = (s * s - x1 - x2) % ec_p
    y3 = (s * (x1 - x3) - y1) % ec_p
    return (x3, y3)


def sub(P, Q):
    return add(P, neg(Q))


M1 = (311807116193896827644739253302305279217, 7855887539980666227955101748628403240)
C1 = (257002431054630264858677428581341658692, 30216239897067040892715927900490561145)
C2 = (37176490317185231572190409936006749595, 156278783123439977215608545494458627497)

M2 = add(sub(M1, C1), C2)
print(M2)
