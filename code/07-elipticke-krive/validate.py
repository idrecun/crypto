from kurs import ec_n, ec_p
import ec


def validate(P):
    if P is None:
        return False
    x, y = P
    if not (0 <= x < ec_p and 0 <= y < ec_p):
        return False
    if not ec.on_curve(P):
        return False
    if ec.mul(ec_n, P) is not None:
        return False
    return True
