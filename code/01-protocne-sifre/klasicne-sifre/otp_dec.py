from PIL import Image
import os
import sys
import random

def xor_bytes(byte_str1, byte_str2):
    return bytes(x ^ y for x, y in zip(byte_str1, byte_str2))


# Check if a file path is provided as a command line argument
if len(sys.argv) != 3:
    print("Usage: python script.py <image_path> <image_path>")
    sys.exit(1)

# Specify the path to the greyscale images
image_path1 = sys.argv[1]
image_path2 = sys.argv[2]

# Open the images
image1 = Image.open(image_path1)
image2 = Image.open(image_path2)

# Convert the images to greyscale
grey_image1 = image1.convert("L")
grey_image2 = image2.convert("L")

# Get the image data as bytes
image_bytes1 = grey_image1.tobytes()
image_bytes2 = grey_image2.tobytes()

# Get decrypted xor of images
decrypted_bytes = xor_bytes(image_bytes1, image_bytes2)

# Save the decrypted image
decrypted_image = Image.frombytes("L", image1.size, decrypted_bytes)
decrypted_image.save("decrypted_image.png")
