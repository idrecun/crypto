from kurs import xor, sponge_f, SPONGE_BLOCK_SIZE, bytes_to_blocks, blocks_to_bytes

def pad(message: bytes, block_size: int) -> bytes:
    padded = message + b"\x80"
    pad_len = (-len(padded)) % block_size  # Koliko fali do punog bloka
    return padded + (b'\x00' * pad_len)

r = 2
c = 6
assert r + c == SPONGE_BLOCK_SIZE

def absorb(state, block):
  absorbed = xor(state[:r], block) + bytes(state[r:])
  return sponge_f(absorbed)

def squeeze(state):
  return state[:r], sponge_f(state)

def sponge(data, output_blocks):
  padded = pad(data, r)
  state = [0] * (r + c)
  for block in bytes_to_blocks(padded, r):
    state = absorb(state, block)
  h = []
  for _ in range(output_blocks):
    output, state = squeeze(state)
    h.append(output)
  return blocks_to_bytes(h)

print(sponge(b"Hello, world!", 4).hex())
