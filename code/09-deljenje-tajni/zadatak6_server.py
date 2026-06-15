# pokretanje učesnika i: python zadatak6_server.py <i> <n> <t>
# (pokrenuti n učesnika; klijent kasnije kontaktira bar t+1)
import sys
import elgamal
import pedersen_dkg
from kurs.network import connect_mesh, Listener

i, n, t = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])

# Faza 1: učesnici zajednički generišu ključ distribuiranim protokolom (DKG),
# bez centralnog delioca. Tajna s se nigde ne rekonstruiše.
listener, peers = connect_mesh(i, n, base_port=12444)
s_i, A = pedersen_dkg.run_dkg_peer(i, n, t, peers)
for conn in peers.values():
    conn.close()
listener.close()

# Faza 2: posluživanje klijenata. Na svaku vezu se prvo objavi zajednički javni
# ključ A, a zatim vrati delimični dešifrat k_i = R^{s_i}.
serve = Listener(port=12344 + i)
serve.start()
print(f"učesnik {i}: DKG gotov, služim na portu {12344 + i} (A = {A})", flush=True)
while True:
    conn, _ = serve.accept()
    conn.send(A)
    R = conn.recv()
    conn.send((i, elgamal.partial_decrypt(R, s_i)))
    conn.close()
