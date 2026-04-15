#!/usr/bin/env bash
set -euo pipefail

IMG="${1:-ecb-lab-ext2.img}"
MNT="./mnt-ecb-inspect"

cleanup() {
    if mountpoint -q "$MNT" 2>/dev/null; then
        sudo umount "$MNT"
    fi
}
trap cleanup EXIT

mkdir -p "$MNT"

echo "Mounting $IMG..."
sudo mount -o loop "$IMG" "$MNT"

echo
echo "=== Files (human-readable sizes) ==="
ls -lh "$MNT"

echo
echo "=== Total payload (sum of file sizes) ==="
du -ch --apparent-size "$MNT" 2>/dev/null | tail -n 1

echo
echo "=== Allocated disk usage ==="
du -sh "$MNT" 2>/dev/null

echo
echo "=== Filesystem usage ==="
df -h "$MNT"

echo
echo "Done. Unmounting..."
