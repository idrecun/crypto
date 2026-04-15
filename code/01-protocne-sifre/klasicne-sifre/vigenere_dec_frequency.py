import json
import sys
import re
from string import ascii_lowercase
from getpass import getpass
from itertools import product


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


def get_divisors(n):
    return [d for d in range(2, n + 1) if n % d == 0]


def get_caesar_keys(text, freq_eng):
    res = []
    for key in ascii_lowercase:
        message = "".join(dec(c, key[i % len(key)]) for i, c in enumerate(text))
        score = analyze(message, freq_eng)
        if score < 0.02:
            res.append(key)
    return res


if len(sys.argv) != 2:
    print("Invalid number of arguments: expected 2")
    exit()

with open("english.json", "r") as file:
    freq_eng = json.load(file)

file_path = sys.argv[1]

ciphertext = ""
with open(file_path, "r") as file:
    ciphertext = file.read()

# Step 1: Find all repeated substrings of length L
# and the pairwise gaps between the repetitions
L = 6
print(f"Generating all {L}-repetition gaps...")
gaps = []
for i in range(len(ciphertext) - L + 1):
    substring = ciphertext[i : i + L]
    gaps.extend(
        match.start() - i for match in re.finditer(substring, ciphertext[i + 1 :])
    )

# Step 2: Build a divisor frequency table and filter out the frequent ones
divisors = {}
for gap in gaps:
    for d in get_divisors(gap):
        if d in divisors:
            divisors[d] += 1
        else:
            divisors[d] = 1

candidates = set()
for d in divisors:
    if divisors[d] > 1:
        candidates.add(d)

print(f"Found {len(candidates)} key length candidates.")

# Step 3: For each possible key length, find the candidates for each key letter and attempt decryption
for length in sorted(candidates):
    print(f"Attempting decryption with key length {length}")
    subtexts = [ciphertext[i::length] for i in range(length)]
    key_candidates = [get_caesar_keys(subtext, freq_eng) for subtext in subtexts]

    for key in ["".join(prod) for prod in product(*key_candidates)]:
        message = "".join(dec(c, key[i % len(key)]) for i, c in enumerate(ciphertext))
        score = analyze(message, freq_eng)
        if score < 0.01:
            print()
            print(f"Possible decryption for key {key} with score {score}")
            print(f"{message}")
