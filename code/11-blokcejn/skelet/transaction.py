"""Transakcije. Dve vrste:

  - transparentne ('t'): troše izlaze po referenci (txid, index), svaki ulaz
    potpisan ECDSA potpisom vlasnika; izlazi su parovi (vlasnik, iznos).
  - skrivene ('z', RingCT): troše izlaz iz prstena lažnjaka, sa slikom ključa,
    pseudo-obavezom i MLSAG potpisom; izlazi su poverljivi (obaveza na iznos +
    dokaz opsega + šifrovan iznos).

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
    # TODO (vežbe): napravi poruku transparent_message(inputs, outputs), potpiši je
    # ECDSA potpisom za svaki ulaz (privkeys[i]) i vrati
    # {"kind": "t", "inputs": ..., "outputs": ..., "sigs": [...]}.
    raise NotImplementedError("make_transparent: potpisati ulaze i sastaviti transakciju")


def make_coinbase(height, owner, reward):
    return {"kind": "cb", "height": height,
            "outputs": [{"owner": owner, "amount": reward}]}


def make_genesis(outputs):
    return {"kind": "genesis", "outputs": outputs}


# --- skrivene (poverljive) transakcije: RingCT --------------------------------
def shielded_message(outputs):
    """Poruka koju potpisuju MLSAG-ovi ulaza — vezuje izlaze transakcije (da se
    potpis ne bi mogao preneti na druge izlaze)."""
    return hash_obj(("z-potpis", outputs))


def make_shielded(inputs_spec, outputs):
    """inputs_spec: lista rečnika sa ključevima ring, ring_keys, Cp, pi, x, z
       (videti ringct.py i wallet.pay_shielded); outputs: poverljivi izlazi."""
    # TODO (vežbe): za svaki ulaz potpiši poruku shielded_message(outputs) MLSAG-om
    # (ringsig.sign(m, ring_keys, Cp, pi, x, z)); slika ključa je sig[0]. Sastavi
    # {"kind": "z", "inputs": [{"ring","Cp","key_image","sig"}...], "outputs": ...}.
    raise NotImplementedError("make_shielded: potpisati ulaze MLSAG-om (RingCT)")
