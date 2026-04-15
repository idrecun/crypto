#!/usr/bin/env python3
from collections import Counter

AES_BLOCK = 16
FS_BLOCK = 1024  # ext2 block size used when creating the image


def human_bytes(n: int) -> str:
    mib = n / (1024 * 1024)
    kib = n / 1024
    return f"{n} B ({kib:.2f} KiB, {mib:.2f} MiB)"


def main() -> None:
    path = "ecb.enc"

    with open(path, "rb") as f:
        data = f.read()

    if len(data) % AES_BLOCK != 0:
        raise ValueError(
            f"File size {len(data)} is not a multiple of AES block size {AES_BLOCK}"
        )
    if len(data) % FS_BLOCK != 0:
        raise ValueError(
            f"File size {len(data)} is not a multiple of filesystem block size {FS_BLOCK}"
        )

    aes_blocks = [data[i : i + AES_BLOCK] for i in range(0, len(data), AES_BLOCK)]
    aes_counts = Counter(aes_blocks)

    zero_cipher, zero_count = aes_counts.most_common(1)[0]

    num_fs_blocks = len(data) // FS_BLOCK
    aes_per_fs = FS_BLOCK // AES_BLOCK

    empty_fs_blocks = 0
    occupied_fs_blocks = 0

    max_run = 0
    current_run = 0

    fs_block_status = []

    for i in range(num_fs_blocks):
        block = data[i * FS_BLOCK : (i + 1) * FS_BLOCK]
        subblocks = [block[j : j + AES_BLOCK] for j in range(0, FS_BLOCK, AES_BLOCK)]

        is_empty_like = all(sb == zero_cipher for sb in subblocks)
        fs_block_status.append(is_empty_like)

        if is_empty_like:
            empty_fs_blocks += 1
            current_run = 0
        else:
            occupied_fs_blocks += 1
            current_run += 1
            if current_run > max_run:
                max_run = current_run

    total_estimate_bytes = occupied_fs_blocks * FS_BLOCK
    max_file_estimate_bytes = max_run * FS_BLOCK

    print("=== AES-level analysis ===")
    print(f"Input file:              {path}")
    print(f"Total size:              {human_bytes(len(data))}")
    print(f"AES block size:          {AES_BLOCK} B")
    print(f"Filesystem block size:   {FS_BLOCK} B")
    print(f"AES blocks per FS block: {aes_per_fs}")
    print(f"Total AES blocks:        {len(aes_blocks)}")
    print()
    print("Most frequent AES ciphertext block")
    print(f"  count: {zero_count}")
    print(f"  hex:   {zero_cipher.hex()}")
    print("  interpretation: likely AES_k(0^128), i.e. encrypted zero block")
    print()

    print("Top 10 AES ciphertext blocks:")
    for idx, (blk, cnt) in enumerate(aes_counts.most_common(10), start=1):
        print(f"  {idx:2d}. {cnt:8d}  {blk.hex()}")
    print()

    print("=== Filesystem-block estimate ===")
    print(f"Total FS blocks:         {num_fs_blocks}")
    print(f"Empty-looking FS blocks: {empty_fs_blocks}")
    print(f"Occupied-looking blocks: {occupied_fs_blocks}")
    print(f"Estimated used space:    {human_bytes(total_estimate_bytes)}")
    print()

    print("=== Largest contiguous occupied region ===")
    print(f"Max occupied run:        {max_run} FS blocks")
    print(f"Max file size estimate:  {human_bytes(max_file_estimate_bytes)}")
    print()
    print("Notes:")
    print("- 'Estimated used space' is an estimate of occupied filesystem blocks,")
    print("  so it includes file data + metadata + slack space.")
    print("- 'Max file size estimate' is only a rough upper bound / heuristic.")
    print("  A contiguous occupied run may contain metadata or multiple files,")
    print("  and a file may be fragmented into multiple runs.")


if __name__ == "__main__":
    main()
