from commitment import commit

poruka = b"poruka1"
c, r = commit(poruka)

print(c.hex(), r.hex())
