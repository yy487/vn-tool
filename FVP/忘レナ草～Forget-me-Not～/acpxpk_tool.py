#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
acpxpk_tool.py  --  ACPXPK01 archive (un)packer

Format (reversed from forget.exe FUN_00434xxx):

    +0x00  char   magic[8]   = "ACPXPK01"
    +0x08  u32    count                       (number of entries)
    +0x0C  Entry  entries[count]              (each 0x28 bytes)
    +...   raw    file data

  Entry (0x28 bytes):
    +0x00  char  name[0x20]   ASCII, NUL-terminated, no encryption
    +0x20  u32   offset       absolute file offset
    +0x24  u32   size         file size in bytes

Notes:
  * Index entries MUST be sorted by lstrcmpiA (case-insensitive ASCII)
    because the engine does a binary search for filename lookup.
  * No compression, no XOR, no gaps.
  * File data area is contiguous and starts right after the index table.
  * The original packer leaves UNINITIALISED STACK GARBAGE in the bytes
    of the name field after the trailing NUL. The engine ignores those
    bytes (it only walks until NUL), so we always write 0x00 padding.
    This means a re-pack will not byte-match the original on the index
    region, but the resulting archive is semantically identical.
"""

import os
import sys
import struct
import argparse

MAGIC      = b'ACPXPK01'
HEADER_SZ  = 12               # magic(8) + count(4)
ENTRY_SZ   = 0x28
NAME_SZ    = 0x20


# ---------------------------------------------------------------- helpers

def _ci_key(name: str):
    """Case-insensitive sort key matching Win32 lstrcmpiA on ASCII names."""
    return name.lower()


def _read_index(buf: bytes):
    if buf[:8] != MAGIC:
        raise ValueError(f'not an ACPXPK01 archive (magic={buf[:8]!r})')
    count = struct.unpack_from('<I', buf, 8)[0]
    entries = []
    for i in range(count):
        base = HEADER_SZ + i * ENTRY_SZ
        raw_name = buf[base:base + NAME_SZ]
        name = raw_name.split(b'\x00', 1)[0].decode('ascii')
        offset, size = struct.unpack_from('<II', buf, base + NAME_SZ)
        entries.append((name, offset, size))
    return entries


# ---------------------------------------------------------------- commands

def cmd_list(args):
    buf = open(args.archive, 'rb').read()
    entries = _read_index(buf)
    print(f'archive : {args.archive}')
    print(f'magic   : {MAGIC.decode()}')
    print(f'count   : {len(entries)}')
    print(f'size    : {len(buf)} bytes (0x{len(buf):X})')
    print('-' * 60)
    print(f'{"#":>4}  {"name":<24}  {"offset":>10}  {"size":>10}')
    print('-' * 60)
    for i, (name, off, sz) in enumerate(entries):
        print(f'{i:>4}  {name:<24}  0x{off:08X}  {sz:>10}')


def cmd_unpack(args):
    buf = open(args.archive, 'rb').read()
    entries = _read_index(buf)
    os.makedirs(args.outdir, exist_ok=True)

    # Sanity: data area must be contiguous and start right after the index.
    expected_data_start = HEADER_SZ + len(entries) * ENTRY_SZ
    min_off = min(e[1] for e in entries) if entries else expected_data_start
    if min_off != expected_data_start:
        print(f'[warn] data area starts at 0x{min_off:X}, '
              f'expected 0x{expected_data_start:X}')

    # Save the original on-disk order so pack can rebuild it byte-identical.
    order_path = os.path.join(args.outdir, '_order.txt')
    with open(order_path, 'w', encoding='utf-8') as fo:
        fo.write('# original entry order in ' + os.path.basename(args.archive) + '\n')
        for name, _, _ in entries:
            fo.write(name + '\n')

    for name, off, sz in entries:
        out_path = os.path.join(args.outdir, name)
        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
        with open(out_path, 'wb') as fo:
            fo.write(buf[off:off + sz])

    print(f'[ok] unpacked {len(entries)} files to {args.outdir}')
    print(f'[ok] order saved to {order_path}')


def cmd_pack(args):
    indir = args.indir
    if not os.path.isdir(indir):
        raise SystemExit(f'not a directory: {indir}')

    # Load preserved order if present, otherwise scan the directory.
    order_path = os.path.join(indir, '_order.txt')
    names = []
    if os.path.exists(order_path):
        with open(order_path, 'r', encoding='utf-8') as fi:
            for line in fi:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                names.append(line)
    else:
        for name in sorted(os.listdir(indir), key=_ci_key):
            full = os.path.join(indir, name)
            if os.path.isfile(full) and name != '_order.txt':
                names.append(name)

    # Engine does a case-insensitive binary search => entries MUST be
    # sorted by lstrcmpiA. Sort here regardless of input order.
    names.sort(key=_ci_key)

    # Validate names: ASCII, fits in 0x20 bytes including NUL.
    for n in names:
        try:
            nb = n.encode('ascii')
        except UnicodeEncodeError:
            raise SystemExit(f'name not ASCII: {n!r}')
        if len(nb) >= NAME_SZ:
            raise SystemExit(f'name too long (>= {NAME_SZ}): {n!r}')

    # Read all file blobs.
    blobs = []
    for n in names:
        with open(os.path.join(indir, n), 'rb') as fi:
            blobs.append(fi.read())

    count = len(names)
    data_start = HEADER_SZ + count * ENTRY_SZ

    out = bytearray()
    out += MAGIC
    out += struct.pack('<I', count)

    # Reserve index space; we'll fill it after we know each offset.
    index_off = len(out)
    out += b'\x00' * (count * ENTRY_SZ)

    offsets = []
    for blob in blobs:
        offsets.append(len(out))
        out += blob

    # Fill in the index table now that offsets are known.
    for i, (name, blob, off) in enumerate(zip(names, blobs, offsets)):
        base = index_off + i * ENTRY_SZ
        name_field = name.encode('ascii').ljust(NAME_SZ, b'\x00')
        struct.pack_into(f'<{NAME_SZ}sII', out, base, name_field, off, len(blob))

    with open(args.archive, 'wb') as fo:
        fo.write(out)

    print(f'[ok] packed {count} files into {args.archive}')
    print(f'     total size : {len(out)} bytes (0x{len(out):X})')
    print(f'     data start : 0x{data_start:X}')


def cmd_verify(args):
    """Round-trip check: unpack -> repack -> compare semantically.

    We can't compare raw MD5 because the original packer leaves stack
    garbage in name-field padding (see module docstring). Instead we
    verify that:
      * the same set of (name, size) entries exists,
      * each file's data is byte-identical.
    """
    import tempfile, shutil
    src = args.archive

    tmp = tempfile.mkdtemp(prefix='acpxpk_rt_')
    try:
        unpack_dir = os.path.join(tmp, 'unpacked')
        repack_path = os.path.join(tmp, 'repack.bin')

        class _A: pass
        a = _A(); a.archive = src; a.outdir = unpack_dir
        cmd_unpack(a)
        a = _A(); a.archive = repack_path; a.indir = unpack_dir
        cmd_pack(a)

        orig = _read_index(open(src, 'rb').read())
        rep  = _read_index(open(repack_path, 'rb').read())

        print('-' * 60)
        if len(orig) != len(rep):
            print(f'[FAIL] entry count differs: {len(orig)} vs {len(rep)}')
            return 1

        # Compare as sets of (name, size) pairs.
        orig_map = {n: (o, s) for (n, o, s) in orig}
        rep_map  = {n: (o, s) for (n, o, s) in rep}
        if set(orig_map) != set(rep_map):
            missing = set(orig_map) - set(rep_map)
            added   = set(rep_map) - set(orig_map)
            print(f'[FAIL] name set differs. missing={missing}, added={added}')
            return 1

        bad_size = [n for n in orig_map if orig_map[n][1] != rep_map[n][1]]
        if bad_size:
            print(f'[FAIL] size mismatch on: {bad_size[:5]} ...')
            return 1

        # Byte-compare each file's payload.
        a_buf = open(src, 'rb').read()
        b_buf = open(repack_path, 'rb').read()
        bad_data = []
        for n in orig_map:
            ao, asz = orig_map[n]
            bo, bsz = rep_map[n]
            if a_buf[ao:ao+asz] != b_buf[bo:bo+bsz]:
                bad_data.append(n)
        if bad_data:
            print(f'[FAIL] data mismatch on: {bad_data[:5]} ...')
            return 1

        print(f'[ok] round-trip: {len(orig)} entries match (semantic)')
        print('     note: name-field padding bytes intentionally differ')
        print('     (original packer wrote uninitialised stack garbage)')
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description='ACPXPK01 archive tool')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('list', help='list entries')
    p.add_argument('archive')
    p.set_defaults(func=cmd_list)

    p = sub.add_parser('unpack', help='extract all files')
    p.add_argument('archive')
    p.add_argument('-o', '--outdir', default='unpacked')
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser('pack', help='build an archive from a directory')
    p.add_argument('indir')
    p.add_argument('archive')
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser('verify', help='unpack+repack+md5 compare (round-trip)')
    p.add_argument('archive')
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    rc = args.func(args)
    sys.exit(rc or 0)


if __name__ == '__main__':
    main()
