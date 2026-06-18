"""Napad: pokušaj trošenja tuđeg izlaza bez privatnog ključa.

Napadač vidi transparentni izlaz čvora 1 i pokušava da ga prebaci sebi. Bez
žrtvinog privatnog ključa ne može da napravi validan potpis, pa lanac transakciju
odbija. (Da provera potpisa ne postoji — kao u skeletonu pre nego što je
implementiramo — krađa bi prošla; zato je upravo ta provera suština.)

Pokretanje: python napad_falsifikat.py
"""
import chain as ch
import transaction as tx
from params import node_keys

C = ch.Blockchain.fresh()
victim = node_keys(1)["t_pub"]
victim_op = next(op for op, o in C.state.outputs.items() if o.get("owner") == victim)
attacker = node_keys(9)

inputs = [victim_op]
outputs = [{"owner": attacker["t_pub"], "amount": 100}]

# Potpis napadačevim ključem (nema žrtvin tajni ključ).
t_wrong = tx.make_transparent(inputs, outputs, [attacker["t_priv"]])
print("krađa sa pogrešnim potpisom prihvaćena:", C.accepts(t_wrong))

# Izmišljen potpis.
t_fake = {"kind": "t", "inputs": inputs, "outputs": outputs, "sigs": [(1, 1)]}
print("krađa sa izmišljenim potpisom prihvaćena:", C.accepts(t_fake))

print("-> izlaz može da potroši samo vlasnik privatnog ključa")
