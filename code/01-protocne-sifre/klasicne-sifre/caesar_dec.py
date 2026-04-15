import json
import sys
from string import ascii_lowercase


def dec(c, k):
    if not c.islower():
        return c
    ord_c = ascii_lowercase.index(c)
    ord_k = ascii_lowercase.index(k)
    return ascii_lowercase[(ord_c - ord_k + 26) % 26]


def analyze(message, freq_eng):
    frequencies = {letter: 0.0 for letter in ascii_lowercase}
    for letter in message:
        if letter.islower():
            frequencies[letter] += 1 / len(message)

    score = 0
    for letter in ascii_lowercase:
        score += abs(frequencies[letter] - freq_eng[letter]) / 26

    return score


if len(sys.argv) != 2:
    print("Invalid number of arguments: expected 2")
    exit()

with open("english.json", "r") as file:
    freq_eng = json.load(file)

file_path = sys.argv[1]

ciphertext = ""
with open(file_path, "r") as file:
    ciphertext = file.read()

for key in ascii_lowercase:
    message = "".join(dec(c, key) for c in ciphertext)
    score = analyze(message, freq_eng)
    if score < 0.01:
        print()
        print(f"Possible decryption for key {key} with score {score}")
        print(f"{message}")
