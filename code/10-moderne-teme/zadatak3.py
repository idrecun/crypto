import kzg
from kurs import pairing

q = pairing.q

# Date su obaveze na dva nepoznata polinoma f i g, kao i dokazi njihovih
# vrednosti u tački z (iz gen_zadaci.py). Cilj: napraviti jednu obavezu i jedan
# dokaz za vrednost zbira (f+g)(z), bez poznavanja polinoma.
g2 = ((3123222405771183912285272371589, 889621347109211773105306626444),
      (1389351266281089382217769713980, 4556896886183083855860660768016))
C_f = (4872578499853521075576471873043, 42371335861733313678048266075)
C_g = (3630176008658098532381820265258, 3287681829933959978674934358289)
z = 9
y_f, proof_f = 147037695731468139483416602607, (3925170666202618525851650522922, 2459568489448151586144483654368)
y_g, proof_g = 988119221372610424591420477780, (1947971255417175390759950296149, 5039343611747766020383206342099)

# KZG obaveze i dokazi su homomorfni: C_{f+g} = C_f + C_g, dokaz je proof_f +
# proof_g, a vrednost y_f + y_g. (Sledi iz C_h = h(tau)G i bilinearnosti.)
C_sum = pairing.add(C_f, C_g)
proof_sum = pairing.add(proof_f, proof_g)
y_sum = (y_f + y_g) % q

print(f"(f+g)({z}) = {y_sum}")
print(f"jedan dokaz za zbir validan: {kzg.verify(g2, C_sum, z, y_sum, proof_sum)}")
# Obaveza i dokaz ostaju konstantne veličine (po jedna tačka) bez obzira na
# stepen polinoma — za razliku od Pedersenovih obaveza po koeficijentima.
