import lamport
from zadatak5_data import pk, messages, signatures

# Isti par Lamportovih ključeva je iskorišćen za potpisivanje više poruka
# (pk i potpisi su u zadatak5_data.py). Svaki potpis otkriva, za svaku poziciju
# i, vrednost x_i (ako je bit i heša poruke 0) ili y_i (ako je 1).
target = b"Kvantni pozdrav!"
target_bits = lamport.bits(lamport.h(target))

# Za svaku poziciju i, potreban nam je deo ključa koji odgovara bitu
# target_bits[i]. Ako je neka potpisana poruka na poziciji i imala isti bit kao
# target, onda je odgovarajuća vrednost već otkrivena — prepišemo je.
forged = [None] * lamport.N
for msg, sig in zip(messages, signatures):
    msg_bits = lamport.bits(lamport.h(msg))
    for i in range(lamport.N):
        if msg_bits[i] == target_bits[i]:
            forged[i] = sig[i]

print(f"sve pozicije pokrivene: {all(v is not None for v in forged)}")
print(f"sklopljen potpis za '{target.decode()}' validan: {lamport.verify(pk, target, forged)}")
