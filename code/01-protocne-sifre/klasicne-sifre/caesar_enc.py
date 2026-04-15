import os
import sys
from string import ascii_lowercase
from getpass import getpass

def enc(m, k):
    if not m.islower():
        return m
    ord_m = ascii_lowercase.index(m)
    ord_k = ascii_lowercase.index(k)
    return ascii_lowercase[(ord_m + ord_k) % 26]

message = ""
file_path = ""
if len(sys.argv) == 2:
    file_path = sys.argv[1]
    # If an argument is provided, encrypt the file
    with open(file_path, 'r') as file:
        message = file.read()
else:
    # Read the plaintext message from standard input
    message = input('Enter message: ')


# Read the encryption key from standard input
key = getpass('Enter key: ')

# Encrypt
ciphertext = "".join(enc(m, key) for m in message)

# Output the results
if file_path == "":
    print(f'Ciphertext: {ciphertext}')
else:
    with open('caesar.txt', 'w') as file:
        file.write(ciphertext)
