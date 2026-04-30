import elgamal

ana_priv, ana_pub = elgamal.generate_keys()
boban_priv, boban_pub = elgamal.generate_keys()

with open("zadatak10_keys.py", "w") as f:
    f.write(f"ana_priv = {ana_priv}\n")
    f.write(f"boban_priv = {boban_priv}\n")
    f.write(f"users = {{'ana': {ana_pub}, 'boban': {boban_pub}}}\n")
