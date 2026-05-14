from kurs import ec_G, ec_n
import ec

# Implementacija: ec.add, ec.sub, ec.neg, ec.mul

P = ec_G
Q = ec.add(P, P)
R = ec.add(Q, P)

print(f"G    = {P}")
print(f"2G   = {Q}")
print(f"3G   = {R}")
print(f"3G == G+G+G: {R == ec.add(ec.add(P, P), P)}")
print(f"3G == 3*G:   {R == ec.mul(3, P)}")
print(f"nG   = {ec.mul(ec_n, P)}")
print(f"-G   = {ec.neg(P)}")
print(f"G + (-G) = {ec.add(P, ec.neg(P))}")
