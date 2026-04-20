#!/usr/bin/env python3
"""
AI5WIN v1 ARC Archive Tool - Unpack & Repack
=============================================
Engine: AI5WIN v1 (e.g. LIME、早期 AI5WIN 作品)
Format: MES.ARC / BG.ARC / BGM.ARC / VOICE.ARC / DATA.ARC

Archive structure:
  [0x00]  u32 LE   entry_count
  [0x04]  entry[0] ... entry[count-1]   (each 0x1C = 28 bytes)
  [data area]  contiguous file data

Entry structure (0x1C bytes, encrypted):
  +0x00  20 bytes  filename (ASCII, zero-padded)    XOR 0x55 per byte
  +0x14  u32 LE    file_size                        XOR 0xAA55AA55
  +0x18  u32 LE    file_offset (absolute in ARC)    XOR 0x55AA55AA

Encryption: simple per-byte XOR on index entries; file data is stored unencrypted.
"""

import struct
import argparse
import os
import sys

# ─── Constants ───────────────────────────────────────────────────────
ENTRY_SIZE      = 0x1C      # 28 bytes per entry
NAME_SIZE       = 0x14      # 20 bytes for filename
XOR_BYTE        = 0x55
XOR_SIZE_KEY    = 0xAA55AA55
XOR_OFFSET_KEY  = 0x55AA55AA


def decrypt_entry(raw: bytes) -> tuple:
    """Decrypt a single 0x1C-byte index entry.
    Returns (name: str, offset: int, size: int, raw_decrypted: bytearray)
    """
    buf = bytearray(raw)
    # Step 1: XOR first 0x14 bytes (filename) with 0x55
    for i in range(NAME_SIZE):
        buf[i] ^= XOR_BYTE
    # Step 2: XOR u32 at +0x14 (size) with 0xAA55AA55
    size_val = struct.unpack_from('<I', buf, 0x14)[0] ^ XOR_SIZE_KEY
    struct.pack_into('<I', buf, 0x14, size_val)
    # Step 3: XOR u32 at +0x18 (offset) with 0x55AA55AA
    off_val = struct.unpack_from('<I', buf, 0x18)[0] ^ XOR_OFFSET_KEY
    struct.pack_into('<I', buf, 0x18, off_val)

    name = buf[:NAME_SIZE].rstrip(b'\x00').decode('ascii')
    return name, off_val, size_val, buf


def encrypt_entry(name: str, offset: int, size: int) -> bytes:
    """Encrypt a single index entry for writing.
    Returns 0x1C bytes ready to write into ARC.
    """
    buf = bytearray(ENTRY_SIZE)
    # Write filename (ASCII, zero-padded to 20 bytes)
    name_bytes = name.encode('ascii')
    if len(name_bytes) > NAME_SIZE:
        raise ValueError(f"Filename too long (>{NAME_SIZE} bytes): {name}")
    buf[:len(name_bytes)] = name_bytes

    # Write size and offset (plain)
    struct.pack_into('<I', buf, 0x14, size)
    struct.pack_into('<I', buf, 0x18, offset)

    # Encrypt: XOR size/offset first, then filename bytes
    enc_size = size ^ XOR_SIZE_KEY
    enc_off  = offset ^ XOR_OFFSET_KEY
    struct.pack_into('<I', buf, 0x14, enc_size)
    struct.pack_into('<I', buf, 0x18, enc_off)
    for i in range(NAME_SIZE):
        buf[i] ^= XOR_BYTE

    return bytes(buf)


def unpack(arc_path: str, out_dir: str):
    """Unpack all files from an ARC archive."""
    with open(arc_path, 'rb') as f:
        data = f.read()

    count = struct.unpack_from('<I', data, 0)[0]
    table_end = 4 + count * ENTRY_SIZE
    print(f"Archive: {arc_path}")
    print(f"  Entries: {count}")
    print(f"  Index table: 0x00 - 0x{table_end - 1:X}")
    print(f"  File size: {len(data)} bytes (0x{len(data):X})")
    print()

    os.makedirs(out_dir, exist_ok=True)

    for i in range(count):
        raw = data[4 + i * ENTRY_SIZE : 4 + (i + 1) * ENTRY_SIZE]
        name, offset, size, _ = decrypt_entry(raw)

        if offset + size > len(data):
            print(f"  [!] WARN: {name} extends beyond file (off=0x{offset:X} size=0x{size:X})")
            continue

        file_data = data[offset : offset + size]
        out_path = os.path.join(out_dir, name)
        with open(out_path, 'wb') as f:
            f.write(file_data)
        print(f"  [{i:3d}] {name:<20s}  off=0x{offset:08X}  size={size:>8d}")

    print(f"\nDone. {count} files extracted to {out_dir}/")


def pack(in_dir: str, arc_path: str, order_file: str = None):
    """Pack files from a directory into an ARC archive.

    If order_file is provided, it should list filenames in desired order (one per line).
    Otherwise, files are sorted alphabetically (matching typical engine expectations).
    """
    # Determine file list and order
    if order_file and os.path.exists(order_file):
        with open(order_file, 'r') as f:
            file_list = [line.strip() for line in f if line.strip()]
        print(f"Using file order from: {order_file} ({len(file_list)} entries)")
    else:
        file_list = sorted(os.listdir(in_dir))
        # Filter out non-files (directories, hidden files)
        file_list = [fn for fn in file_list
                     if os.path.isfile(os.path.join(in_dir, fn)) and fn != '_order.txt']

    count = len(file_list)
    table_size = 4 + count * ENTRY_SIZE   # header + all entries
    print(f"Packing {count} files into {arc_path}")
    print(f"  Index table size: 0x{table_size:X}")

    # Read all files and compute offsets
    entries = []
    current_offset = table_size  # data starts right after index table

    for fn in file_list:
        fpath = os.path.join(in_dir, fn)
        with open(fpath, 'rb') as f:
            fdata = f.read()
        entries.append((fn, current_offset, len(fdata), fdata))
        current_offset += len(fdata)

    # Build archive
    with open(arc_path, 'wb') as f:
        # Write count
        f.write(struct.pack('<I', count))
        # Write encrypted index entries
        for fn, offset, size, _ in entries:
            f.write(encrypt_entry(fn, offset, size))
        # Write file data
        for fn, offset, size, fdata in entries:
            f.write(fdata)

    total_size = current_offset
    print(f"  Total size: {total_size} bytes (0x{total_size:X})")
    print(f"Done. Written to {arc_path}")


def list_arc(arc_path: str):
    """List contents of an ARC archive."""
    with open(arc_path, 'rb') as f:
        data = f.read()

    count = struct.unpack_from('<I', data, 0)[0]
    print(f"Archive: {arc_path}")
    print(f"  Entries: {count}")
    print(f"  File size: {len(data)} bytes")
    print()
    print(f"  {'#':>3s}  {'Name':<20s}  {'Offset':>10s}  {'Size':>10s}")
    print(f"  {'---':>3s}  {'----':<20s}  {'------':>10s}  {'----':>10s}")

    total_data = 0
    for i in range(count):
        raw = data[4 + i * ENTRY_SIZE : 4 + (i + 1) * ENTRY_SIZE]
        name, offset, size, _ = decrypt_entry(raw)
        print(f"  {i:3d}  {name:<20s}  0x{offset:08X}  {size:>10d}")
        total_data += size

    print(f"\n  Total data: {total_data} bytes")


def verify(arc_path: str, ref_dir: str):
    """Verify: unpack ARC and compare with reference directory (round-trip test)."""
    with open(arc_path, 'rb') as f:
        data = f.read()

    count = struct.unpack_from('<I', data, 0)[0]
    ok = 0
    fail = 0

    for i in range(count):
        raw = data[4 + i * ENTRY_SIZE : 4 + (i + 1) * ENTRY_SIZE]
        name, offset, size, _ = decrypt_entry(raw)
        arc_data = data[offset : offset + size]

        ref_path = os.path.join(ref_dir, name)
        if not os.path.exists(ref_path):
            print(f"  [MISS] {name} not found in reference dir")
            fail += 1
            continue

        with open(ref_path, 'rb') as f:
            ref_data = f.read()

        if arc_data == ref_data:
            ok += 1
        else:
            print(f"  [FAIL] {name}: ARC={len(arc_data)}B vs REF={len(ref_data)}B")
            fail += 1

    print(f"\nVerification: {ok} PASS, {fail} FAIL out of {count}")
    return fail == 0


def main():
    parser = argparse.ArgumentParser(
        description='AI5WIN v1 ARC Archive Tool (Unpack / Repack / List / Verify)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s unpack MES.ARC mes_out/
  %(prog)s pack   mes_out/ MES_NEW.ARC
  %(prog)s pack   mes_out/ MES_NEW.ARC --order mes_out/_order.txt
  %(prog)s list   MES.ARC
  %(prog)s verify MES_NEW.ARC mes_out/
""")
    sub = parser.add_subparsers(dest='cmd')

    p_unpack = sub.add_parser('unpack', help='Extract all files from ARC')
    p_unpack.add_argument('arc', help='Input ARC file')
    p_unpack.add_argument('outdir', help='Output directory')

    p_pack = sub.add_parser('pack', help='Pack files into ARC')
    p_pack.add_argument('indir', help='Input directory')
    p_pack.add_argument('arc', help='Output ARC file')
    p_pack.add_argument('--order', help='File order list (one filename per line)')

    p_list = sub.add_parser('list', help='List ARC contents')
    p_list.add_argument('arc', help='Input ARC file')

    p_verify = sub.add_parser('verify', help='Verify ARC against extracted files')
    p_verify.add_argument('arc', help='ARC file to verify')
    p_verify.add_argument('refdir', help='Reference directory with extracted files')

    args = parser.parse_args()
    if args.cmd == 'unpack':
        unpack(args.arc, args.outdir)
    elif args.cmd == 'pack':
        pack(args.indir, args.arc, args.order)
    elif args.cmd == 'list':
        list_arc(args.arc)
    elif args.cmd == 'verify':
        ok = verify(args.arc, args.refdir)
        sys.exit(0 if ok else 1)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
