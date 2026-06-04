import pedersen_dkg

# Pedersenovo distribuirano generisanje ključa: dobijaju se delovi tajne i
# zajednički javni ključ A (tajna s se nigde ne rekonstruiše).
final, A = pedersen_dkg.run_dkg(n=5, t=2)

with open("zadatak5_keys.py", "w") as f:
    f.write(f"A = {A}\n")
    f.write(f"shares = {dict(final)}\n")
