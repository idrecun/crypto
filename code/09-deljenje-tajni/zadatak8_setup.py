import pedersen_dkg

# Distribuirano generisanje ključa: delovi tajne i zajednički javni ključ A.
final, A = pedersen_dkg.run_dkg(n=5, t=2)

with open("zadatak8_keys.py", "w") as f:
    f.write(f"A = {A}\n")
    f.write(f"shares = {dict(final)}\n")
