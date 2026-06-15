import ec_schnorr

client_priv, client_pub = ec_schnorr.generate_keys()
server_priv, server_pub = ec_schnorr.generate_keys()

with open("zadatak7_keys.py", "w") as f:
    f.write(f"client_priv = {client_priv}\n")
    f.write(f"client_pub = {client_pub}\n")
    f.write(f"server_priv = {server_priv}\n")
    f.write(f"server_pub = {server_pub}\n")
