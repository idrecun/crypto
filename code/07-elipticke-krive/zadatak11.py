import ec
from pohlig_hellman import pohlig_hellman

# kriva y^2 = x^3 + 1 nad F_p
p = 1940158473524142299
a = 0
n = 1940158473524142300

G = (17, 213329057279393933)
A = (1057509392935454215, 1290626223251531797)

x = pohlig_hellman(G, A, n, a, p)
print(f"a = {x}")
print(f"provera: aG == A: {ec.mul(x, G, a, p) == A}")
