import rsa

d, (n, e) = rsa.generate_keys()

with open("zadatak8_keys.py", "w") as f:
    f.write(f"server_priv = {d}\n")
    f.write(f"server_pub = ({n}, {e})\n")
