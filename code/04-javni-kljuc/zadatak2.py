import secrets

p = 804455613497485373990731588387
g = 2

A = 524347013556703057489464193864
B = 672823340861902417431101467671
e = 580068529088705669745084345056

Ka = pow(A, e, p)
Kb = pow(B, e, p)

print("Zajednički ključ sa Anom:", Ka)
print("Zajednički ključ sa Bobanom:", Kb)
