"""Lamportov jednokratni potpis (igračka veličina N = 64 bita).

Tajni ključ je niz od N parova slučajnih vrednosti (x_i, y_i). Javni ključ su
heševi tih vrednosti (h(x_i), h(y_i)). Potpis poruke m otkriva, za svaki bit
heša h(m), vrednost x_i (ako je bit 0) ili y_i (ako je bit 1).

U praksi je N = 256; ovde je smanjeno radi čitljivosti konkretnih primera.
"""

import hashlib
import secrets

N = 64  # dužina izlaza heša u bitovima


def h(x: bytes) -> bytes:
    """Igračka heš funkcija: SHA-256 skraćen na N bitova."""
    return hashlib.sha256(x).digest()[: N // 8]


def bits(data: bytes):
    """Bitovi bajtova, od najznačajnijeg."""
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]


def keygen():
    """Vrati (sk, pk). sk je lista parova (x_i, y_i), pk lista (h(x_i), h(y_i))."""
    sk = [(secrets.token_bytes(N // 8), secrets.token_bytes(N // 8)) for _ in range(N)]
    pk = [(h(x), h(y)) for (x, y) in sk]
    return sk, pk


def sign(sk, m: bytes):
    """Potpis: za svaki bit heša poruke otkrij odgovarajuću tajnu vrednost."""
    b = bits(h(m))
    return [sk[i][b[i]] for i in range(N)]


def verify(pk, m: bytes, sig):
    """Proveri da je heš svake otkrivene vrednosti jednak delu javnog ključa."""
    b = bits(h(m))
    return all(h(sig[i]) == pk[i][b[i]] for i in range(N))


if __name__ == "__main__":
    sk, pk = keygen()
    m = b"Kvantni pozdrav!"
    sig = sign(sk, m)
    print(f"potpis validan: {verify(pk, m, sig)}")
    print(f"druga poruka: {verify(pk, b'Druga poruka', sig)}")
