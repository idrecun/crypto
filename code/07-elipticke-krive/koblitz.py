from kurs import ec_a, ec_b, ec_p

K = 1024


def encode(m, k=K):
    for i in range(k):
        x = m * k + i
        if x >= ec_p:
            break
        rhs = (x * x * x + ec_a * x + ec_b) % ec_p
        if pow(rhs, (ec_p - 1) // 2, ec_p) == 1:
            y = pow(rhs, (ec_p + 1) // 4, ec_p)
            return (x, y)
    raise ValueError("enkodovanje nije uspelo")


def decode(P, k=K):
    return P[0] // k
