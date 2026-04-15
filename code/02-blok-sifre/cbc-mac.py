from kurs import bytes_to_blocks, xor
import modes
import spn

def mac(cipher, key: bytes, message: bytes) -> bytes:
  blocks = bytes_to_blocks(message, cipher.block_size)
  stream = [int.to_bytes(0, cipher.block_size)] # Prvi blok je IV = 0
  for block in blocks:
    stream.append(cipher.encrypt_block(key, xor(block, stream[-1])))
  return stream[-1]

def verify(cipher, key: bytes, message: bytes, tag: bytes) -> bool:
  return mac(cipher, key, message) == tag

def mac_fixed(cipher, key: bytes, message: bytes) -> bytes:
  length = int.to_bytes(len(message), cipher.block_size)
  blocks = [length] + bytes_to_blocks(message, cipher.block_size)
  stream = [int.to_bytes(0, cipher.block_size)]
  for block in blocks:
    stream.append(cipher.encrypt_block(key, xor(block, stream[-1])))
  return stream[-1]

def verify_fixed(cipher, key: bytes, message: bytes, tag: bytes) -> bool:
    return mac_fixed(cipher, key, message) == tag

poruka = b"ana voli milovana"
key = b"matfcryptography"
tag = mac(spn, key, modes.pad(spn, poruka))

print(f"Tag: {tag.hex()}")
print(verify(spn, key, modes.pad(spn, poruka), tag))

tag_fixed = mac_fixed(spn, key, modes.pad(spn, poruka))

print(f"Tag fixed: {tag_fixed.hex()}")
print(verify_fixed(spn, key, modes.pad(spn, poruka), tag_fixed))

