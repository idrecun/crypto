import feistel
import modes
import spn


def demo_spn_cbc():
    key = b"matfcryptography"
    iv = b"12345678"
    message = b"blok sifre na vezbama"

    padded = modes.pad(spn, message)
    ciphertext = modes.encrypt_cbc(spn, key, padded, iv)
    decrypted = modes.decrypt_cbc(spn, key, ciphertext)
    restored = modes.unpad(spn, decrypted)

    print("SPN + CBC:", restored)


def demo_feistel_ctr():
    key = b"matfcryptography"
    nonce = 7
    message = b"ctr ne zahteva padding"

    ciphertext = modes.encrypt_ctr(feistel, key, message, nonce)
    decrypted = modes.decrypt_ctr(feistel, key, ciphertext, nonce)

    print("Feistel + CTR:", decrypted)


def demo_spn_ecb():
    key = b"matfcryptography"
    message = b"ecb primer poruke"

    padded = modes.pad(spn, message)
    ciphertext = modes.encrypt_ecb(spn, key, padded)
    decrypted = modes.decrypt_ecb(spn, key, ciphertext)
    restored = modes.unpad(spn, decrypted)

    print("SPN + ECB:", restored)


if __name__ == "__main__":
    demo_spn_cbc()
    demo_feistel_ctr()
    demo_spn_ecb()
