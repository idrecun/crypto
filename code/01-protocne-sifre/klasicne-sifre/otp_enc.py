from PIL import Image
import os
import sys
import random


def generate_random_bytes(length):
    random.seed(0)
    return bytes(random.randint(0, 255) for _ in range(length))


def xor_bytes(byte_str1, byte_str2):
    return bytes(x ^ y for x, y in zip(byte_str1, byte_str2))


# Check if a file path is provided as a command line argument
if len(sys.argv) != 2:
    print("Usage: python script.py <image_path>")
    sys.exit(1)

# Specify the path to the greyscale image
image_path = sys.argv[1]

# Open the image
image = Image.open(image_path)

# Convert the image to greyscale
grey_image = image.convert("L")

# Get the image data as bytes
image_bytes = grey_image.tobytes()

# Generate random bytes with the same length as the image data
random_bytes = generate_random_bytes(len(image_bytes))

# XOR the image data with the random bytes
ciphertext_bytes = xor_bytes(image_bytes, random_bytes)

# Save the encrypted image
image_name, _ = os.path.splitext(image_path)
encrypted_image = Image.frombytes("L", image.size, ciphertext_bytes)
encrypted_image.save(f"{image_name}.enc.png")
