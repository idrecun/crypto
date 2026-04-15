import commitment

# Pretpostavljamo da je skup mogucih poruka mali
moguce_poruke = [b"poruka1", b"poruka2", b"poruka3"]

c, r = map(bytes.fromhex, input().split())

for poruka in moguce_poruke:
    if commitment.verify(poruka, c, r):
        print(f"Poruka je: {poruka}")
