from kurs import ec_G
import validate

# Implementacija: validate.validate

candidates = {
    "G (validan)": ec_G,
    "(1, 1) (nije na krivoj)": (1, 1),
    "tacka u beskonacnosti": None,
}

for label, P in candidates.items():
    print(f"{label}: {validate.validate(P)}")
