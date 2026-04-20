#!/usr/bin/env python3
"""
fizz_tool.py - Fizz/l-soft .gsp archive unpack/repack

Format (no compression, no encryption):
    u32    count
    count x {
        u32   offset        ; absolute, from start of file
        u32   size
        char  name[56]      ; CP932, NUL-padded
    }
    <data blob>             ; files back-to-back starting right after header

Header total = 4 + count * 64.
First entry's offset equals the header size.
Last entry's offset+size equals the file size.

Usage:
    python fizz_tool.py unpack  <archive.gsp> <out_dir>
    python fizz_tool.py repack  <in_dir>      <archive.gsp>
    python fizz_tool.py list    <archive.gsp>
"""
import os, sys, struct, argparse

ENTRY_SIZE = 0x40
NAME_LEN   = 56   # 64 - 8
HEADER_FMT = '<I'

def read_index(data):
    count = struct.unpack_from('<I', data, 0)[0]
    entries = []
    for i in range(count):
        base = 4 + i * ENTRY_SIZE
        off, size = struct.unpack_from('<II', data, base)
        raw_name = data[base + 8 : base + 8 + NAME_LEN]
        name = raw_name.split(b'\x00', 1)[0].decode('cp932')
        entries.append((off, size, name))
    return entries

def cmd_list(arc_path):
    with open(arc_path, 'rb') as f:
        data = f.read()
    entries = read_index(data)
    print(f'{len(entries)} files, archive size {len(data):#x}')
    for off, size, name in entries:
        print(f'  {off:#010x}  {size:#10x}  {name}')

def cmd_unpack(arc_path, out_dir):
    with open(arc_path, 'rb') as f:
        data = f.read()
    entries = read_index(data)
    os.makedirs(out_dir, exist_ok=True)

    # Preserve original on-disk order for bit-perfect repack
    order_path = os.path.join(out_dir, '_order.txt')
    with open(order_path, 'w', encoding='utf-8', newline='\n') as od:
        for off, size, name in entries:
            od.write(f'{name}\n')

    for off, size, name in entries:
        # Keep original name; strip any path chars just in case
        safe = name.replace('/', '_').replace('\\', '_')
        out_path = os.path.join(out_dir, safe)
        with open(out_path, 'wb') as out:
            out.write(data[off : off + size])
    print(f'[OK] unpacked {len(entries)} files -> {out_dir}')
    print(f'     _order.txt saved for repack')

def cmd_repack(in_dir, arc_path):
    order_path = os.path.join(in_dir, '_order.txt')
    if os.path.exists(order_path):
        with open(order_path, 'r', encoding='utf-8') as od:
            names = [line.rstrip('\n') for line in od if line.strip()]
    else:
        # fallback: alphabetical
        names = sorted(os.listdir(in_dir))
        names = [n for n in names if not n.startswith('_')]

    count = len(names)
    header_size = 4 + count * ENTRY_SIZE

    # Build header + data
    file_bodies = []
    index = []  # (offset, size, name)
    cur = header_size
    for name in names:
        path = os.path.join(in_dir, name)
        with open(path, 'rb') as f:
            body = f.read()
        index.append((cur, len(body), name))
        file_bodies.append(body)
        cur += len(body)

    with open(arc_path, 'wb') as out:
        out.write(struct.pack('<I', count))
        for off, size, name in index:
            name_enc = name.encode('cp932')
            if len(name_enc) > NAME_LEN:
                raise ValueError(f'name too long ({len(name_enc)} > {NAME_LEN}): {name}')
            name_padded = name_enc + b'\x00' * (NAME_LEN - len(name_enc))
            out.write(struct.pack('<II', off, size) + name_padded)
        for body in file_bodies:
            out.write(body)
    print(f'[OK] repacked {count} files -> {arc_path} ({cur:#x} bytes)')

def main():
    ap = argparse.ArgumentParser(description='Fizz/l-soft .gsp archive tool')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('unpack'); p.add_argument('arc'); p.add_argument('out_dir')
    p = sub.add_parser('repack'); p.add_argument('in_dir'); p.add_argument('arc')
    p = sub.add_parser('list');   p.add_argument('arc')

    args = ap.parse_args()
    if   args.cmd == 'unpack': cmd_unpack(args.arc, args.out_dir)
    elif args.cmd == 'repack': cmd_repack(args.in_dir, args.arc)
    elif args.cmd == 'list':   cmd_list(args.arc)

if __name__ == '__main__':
    main()
