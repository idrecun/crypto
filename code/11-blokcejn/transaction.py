"""Transakcije. Dve vrste:

  - transparentne ('t'): troše izlaze po referenci (txid, index), svaki ulaz
    potpisan ECDSA potpisom vlasnika; izlazi su parovi (vlasnik, iznos).
  - skrivene ('z'): troše izlaz iz prstena lažnjaka, sa slikom ključa i
    prstenastim potpisom; izlazi su stealth parovi (R, P). Novčići su jedinične
    denominacije, pa je bilans zadovoljen kada je broj ulaza == broj izlaza.

Pored toga, 'cb' je nagradna (coinbase) transakcija bloka, a 'genesis' početni
upis novca. Identifikator transakcije je heš cele transakcije (uključujući
potpise — tako promena potpisa menja txid, što koristimo u napadu kovkošću).
"""
from kurs import hash_obj
import ecdsa
import ringsig


def txid(tx):
    return hash_obj(tx)


# --- transparentne transakcije ----------------------------------------------
def transparent_message(inputs, outputs):
    """Poruka koju potpisuju vlasnici ulaza (ne uključuje same potpise)."""
    return hash_obj(("t-potpis", inputs, outputs))


def make_transparent(inputs, outputs, privkeys):
    msg = transparent_message(inputs, outputs)
    sigs = [ecdsa.sign(msg, sk) for sk in privkeys]
    return {"kind": "t", "inputs": inputs, "outputs": outputs, "sigs": sigs}


def make_coinbase(height, owner, reward):
    return {"kind": "cb", "height": height,
            "outputs": [{"owner": owner, "amount": reward}]}


def make_genesis(outputs):
    return {"kind": "genesis", "outputs": outputs}


# --- skrivene (poverljive) transakcije: RingCT --------------------------------
def shielded_message(outputs):
    """Poruka koju potpisuju MLSAG-ovi ulaza — vezuje izlaze transakcije (da se
    potpis ne bi mogao preneti na druge izlaze). Prsten, sliku ključa i
    pseudo-obavezu svakog ulaza MLSAG dodatno vezuje kroz svoj izazov."""
    return hash_obj(("z-potpis", outputs))


def make_shielded(inputs_spec, outputs):
    """inputs_spec: lista rečnika sa ključevima
         ring       - reference (txid, index) članova prstena,
         ring_keys  - odgovarajući parovi (P_i, C_i) (jednokratni ključ, obaveza),
         Cp         - pseudo-obaveza C' na iznos ovog ulaza,
         pi         - indeks pravog (našeg) izlaza u prstenu,
         x          - jednokratni privatni ključ tog izlaza,
         z          - b_in − b' (tako da je C_pi − C' obaveza na nulu).
       outputs: poverljivi izlazi {'R','P','C','range','enc'} (videti ringct.py)."""
    m = shielded_message(outputs)
    inputs = []
    for spec in inputs_spec:
        sig = ringsig.sign(m, spec["ring_keys"], spec["Cp"], spec["pi"], spec["x"], spec["z"])
        inputs.append({"ring": spec["ring"], "Cp": spec["Cp"],
                       "key_image": sig[0], "sig": sig})
    return {"kind": "z", "inputs": inputs, "outputs": outputs}
