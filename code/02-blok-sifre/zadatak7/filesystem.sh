#!/usr/bin/env bash
set -euo pipefail

IMG="ecb-lab-ext2.img"
MNT="./mnt-ecb-lab"

cleanup() {
    if mountpoint -q "$MNT" 2>/dev/null; then
        sudo umount "$MNT"
    fi
}
trap cleanup EXIT

rm -f "$IMG"
mkdir -p "$MNT"

# 64 MiB image: still easy to handle, but large enough that metadata matters less.
truncate -s 64M "$IMG"

# Create a simple ext2 filesystem in the regular file.
# -F      allow formatting a regular file
# -b 1024 use 1 KiB blocks for easier manual inspection
# -m 0    no reserved blocks
sudo mkfs.ext2 \
  -F \
  -b 1024 \
  -m 0 \
  -L ECBLAB \
  "$IMG"

# Mount it as a loopback filesystem.
sudo mount -o loop "$IMG" "$MNT"
sudo chown "$(id -u):$(id -g)" "$MNT"

# File 1: repeat.bin
# Based on the earlier small version, but repeated many times.
python3 - <<'PY'
from pathlib import Path

base = (b"ABCD" * 256) * 3 + (b"TAIL1" * 17)
repeat_count = 400
data = base * repeat_count
Path("mnt-ecb-lab/repeat.bin").write_bytes(data)
print("repeat.bin size:", len(data))
PY

# File 2: structured.bin
# Same structured pattern as before, repeated many times.
python3 - <<'PY'
from pathlib import Path

base = bytearray(5000)
base[0:32] = b"HEADER-START-0123456789ABCDEFGH"
base[1024:1024+64] = b"X" * 64
base[2048:2048+128] = b"Y" * 128
base[4096:4096+32] = b"FOOTER-XYZ-1234567890-TAIL-END!!"

repeat_count = 250
data = bytes(base) * repeat_count
Path("mnt-ecb-lab/structured.bin").write_bytes(data)
print("structured.bin size:", len(data))
PY

# File 3: notes.txt
# Same idea as before, but repeated many times to make it substantial.
python3 - <<'PY'
from pathlib import Path

base = (
    b"This is a small plaintext file.\n"
    b"It has multiple lines.\n"
    b"It is intentionally different from the binary-looking files.\n"
    b"ECB on raw disk blocks may still leak structure, repeated blocks, and size clues.\n"
)

repeat_count = 2000
data = base * repeat_count
Path("mnt-ecb-lab/notes.txt").write_bytes(data)
print("notes.txt size:", len(data))
PY

sync

echo
echo "=== Files created ==="
ls -lh "$MNT"

echo
echo "=== Filesystem usage ==="
df -h "$MNT" || true
du -sh "$MNT" || true

echo
echo "=== Block/extents for each file ==="
filefrag -v "$MNT/repeat.bin" || true
filefrag -v "$MNT/structured.bin" || true
filefrag -v "$MNT/notes.txt" || true

echo
echo "=== Filesystem info ==="
dumpe2fs -h "$IMG" 2>/dev/null | grep -E 'Filesystem volume name|Block size|Block count|Free blocks|Inode count|Free inodes|Filesystem features' || true

echo
echo "Image ready: $IMG"
echo "Mounted at:  $MNT"
echo
echo "Useful inspection commands:"
echo "  xxd -g 1 $IMG | less"
echo "  hexdump -C $IMG | less"
echo "  debugfs $IMG"
echo
echo "When done:"
echo "  sudo umount $MNT"
