from kurs import xor

pbox_table = [7, 3, 6, 2, 5, 1, 4, 0]
pinv_table = [7, 5, 3, 1, 6, 4, 2, 0]

def pbox(block: bytes) -> bytes:
  return bytes(block[i] for i in pbox_table)

def pinv(block: bytes) -> bytes:
  return bytes(block[i] for i in pinv_table)

def encrypt_block(key: bytes, block: bytes) -> bytes:
  assert len(block) == 8
  assert len(key) == 32
  keys = [key[i:i+8] for i in range(0, 32, 8)]
  for k in keys[0:-1]:
    block = xor(block, k)
    block = pbox(block)
  block = xor(block, keys[-1])
  return block

m0 = bytes.fromhex("506f7a6472617621")
c0 = bytes.fromhex("217925342f722150")
c1 = bytes.fromhex("216225222a782f4e")

const = xor(c0, pbox(pbox(pbox(m0))))
m1 = pinv(pinv(pinv(xor(c1, const))))
print(m1)
