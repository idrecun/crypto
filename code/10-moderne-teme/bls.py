"""BLS potpisi nad igračkim uparivanjem iz kurs.pairing.

Tajni ključ je skalar a, javni ključ A = aG. Potpis poruke m je S = a H(m),
gde H slika poruku u tačku grupe. Provera: e(S, G) = e(H(m), A).

Više potpisa iste poruke se agregira u multipotpis: zajednički javni ključ je
apk = sum A_i, a agregirani potpis S = sum S_i. Provera je e(S, G) =
e(H(m), apk).
"""

from kurs import pairing

G = pairing.G
q = pairing.q


def keygen(a):
    """Javni ključ A = aG za tajni ključ a."""
    return pairing.mul(a % q, G)


def sign(a, m: bytes):
    """Potpis S = a H(m)."""
    return pairing.mul(a % q, pairing.hash_to_point(m))


def verify(A, m: bytes, S):
    """e(S, G) == e(H(m), A)."""
    return pairing.pairing(S, G) == pairing.pairing(pairing.hash_to_point(m), A)


def aggregate_pubkey(pubkeys):
    """Zajednički javni ključ multipotpisa apk = sum A_i."""
    apk = None
    for Ai in pubkeys:
        apk = pairing.add(apk, Ai)
    return apk


def aggregate_sign(sigs):
    """Agregirani potpis S = sum S_i."""
    S = None
    for Si in sigs:
        S = pairing.add(S, Si)
    return S


def verify_multisig(apk, m: bytes, S):
    """Provera multipotpisa: e(S, G) == e(H(m), apk)."""
    return pairing.pairing(S, G) == pairing.pairing(pairing.hash_to_point(m), apk)


if __name__ == "__main__":
    import secrets

    a = secrets.randbelow(q)
    A = keygen(a)
    m = b"Zdravo, BLS!"
    S = sign(a, m)
    print(f"potpis validan: {verify(A, m, S)}")
    print(f"izmenjena poruka: {verify(A, b'Zdravo, BLZ!', S)}")

    # multipotpis tri potpisnika nad istom porukom
    keys = [secrets.randbelow(q) for _ in range(3)]
    pubs = [keygen(a) for a in keys]
    sigs = [sign(a, m) for a in keys]
    apk = aggregate_pubkey(pubs)
    S_agg = aggregate_sign(sigs)
    print(f"multipotpis validan: {verify_multisig(apk, m, S_agg)}")
