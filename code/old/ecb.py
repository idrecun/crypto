#!/usr/bin/env python3
"""
Encrypt an image with AES-ECB to demonstrate why ECB is bad (pattern leakage).

Usage:
  pip install pillow pycryptodome
  python ecb_image.py input.png output.png --key "YELLOW SUBMARINE"

Notes:
  - Best results with lossless images (PNG/BMP).
  - Encrypts raw pixel bytes; dimensions/mode preserved.
"""

import argparse
from Crypto.Cipher import AES
from PIL import Image


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or (len(data) % block_size) != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def normalize_key(key: bytes) -> bytes:
    # AES key must be 16/24/32 bytes. For a demo, we deterministically pad/truncate to 16.
    if len(key) == 16:
        return key
    if len(key) < 16:
        return key.ljust(16, b"\x00")
    return key[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_image")
    ap.add_argument("output_image")
    ap.add_argument("--key", default="YELLOW SUBMARINE", help="Demo key (will be padded/truncated to 16 bytes)")
    ap.add_argument("--decrypt", action="store_true", help="Decrypt instead of encrypt (for sanity check)")
    args = ap.parse_args()

    key = normalize_key(args.key.encode("utf-8"))
    cipher = AES.new(key, AES.MODE_ECB)

    img = Image.open(args.input_image)
    # Convert to a stable pixel format so we control the byte layout.
    # RGB is usually enough for the classic ECB demo.
    img = img.convert("RGB")

    raw = img.tobytes()  # raw pixel bytes: repeating patterns in image => repeating blocks in ECB
    block_size = 16

    if not args.decrypt:
        padded = pkcs7_pad(raw, block_size)
        enc = cipher.encrypt(padded)
        # Trim back to original length so we can reconstruct image buffer exactly.
        enc = enc[: len(raw)]
        out = Image.frombytes(img.mode, img.size, enc)
        out.save(args.output_image)
    else:
        # Decrypt path assumes the encrypted image was produced by this script.
        enc = raw
        # We don't know original padding now because we trimmed; restore by re-padding to decrypt full blocks.
        enc_padded = pkcs7_pad(enc, block_size)
        dec_padded = cipher.decrypt(enc_padded)
        dec = dec_padded[: len(enc)]
        out = Image.frombytes(img.mode, img.size, dec)
        out.save(args.output_image)


if __name__ == "__main__":
    main()
