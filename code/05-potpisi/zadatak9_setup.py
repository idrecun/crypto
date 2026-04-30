import schnorr

ana_priv, ana_pub = schnorr.generate_keys()

with open("zadatak9_keys.py", "w") as f:
    f.write(f"ana_priv = {ana_priv}\n")
    f.write(f"users = {{'ana': {ana_pub}}}\n")
