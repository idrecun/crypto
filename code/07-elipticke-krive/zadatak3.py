import ec
import koblitz

m = 0x48656C6C6F2C204D617466 # "Hello, Matf"

P = koblitz.encode(m)
print(f"M = {m}")
print(f"P = {P}")
print(f"P na krivoj: {ec.on_curve(P)}")
print(f"dekodovano: {koblitz.decode(P)}")
print(f"poklapanje: {koblitz.decode(P) == m}")
