#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI5WIN V6 ARC Tool
==================
封包格式: mes.arc (AI5WIN V6 引擎)

结构:
  [0x00-0x03] u32 LE     count
  [0x04-....] entry[count]   每个条目 0x26 (38) 字节
    [0x00-0x1D] 30B filename  XOR 0x73, \0 填充
    [0x1E-0x21] u32 size      XOR 0xAF5789BC   <- size 在前 (V5/V6 共同反直觉布局)
    [0x22-0x25] u32 offset    XOR 0x59FACB45   <- offset 在后
  [data area]  每个文件的原始字节 (无压缩头, LZSS 压缩流直接存储)

参考函数: FUN_00401000 (解密) + FUN_00402370 (ARC 加载主函数)
"""

import os
import sys
import struct
import argparse

MAGIC_NAME_XOR = 0x73
KEY_SIZE       = 0xAF5789BC  # 条目偏移 0x1E
KEY_OFFSET     = 0x59FACB45  # 条目偏移 0x22
ENTRY_SIZE     = 0x26        # 38 字节
NAME_LEN       = 0x1E        # 30 字节


def decrypt_name(raw: bytes) -> str:
    """文件名 XOR 0x73, 以 \0 结尾"""
    dec = bytes(b ^ MAGIC_NAME_XOR for b in raw)
    end = dec.find(b'\x00')
    if end < 0:
        end = len(dec)
    return dec[:end].decode('ascii', errors='replace')


def encrypt_name(name: str) -> bytes:
    """文件名编码: 大写 ASCII + \0 填充到 30 字节, 再 XOR 0x73"""
    raw = name.encode('ascii')
    if len(raw) > NAME_LEN:
        raise ValueError(f"Filename too long: {name} ({len(raw)} > {NAME_LEN})")
    raw = raw.ljust(NAME_LEN, b'\x00')
    return bytes(b ^ MAGIC_NAME_XOR for b in raw)


def parse_arc(arc_path: str):
    """解析 ARC 索引表, 返回 [(name, offset, size), ...]"""
    with open(arc_path, 'rb') as f:
        data = f.read()

    count = struct.unpack('<I', data[:4])[0]
    print(f"[+] File count: {count}")

    entries = []
    for i in range(count):
        base = 4 + i * ENTRY_SIZE
        name_raw = data[base : base + NAME_LEN]
        size_enc = struct.unpack('<I', data[base + 0x1E : base + 0x22])[0]
        off_enc  = struct.unpack('<I', data[base + 0x22 : base + 0x26])[0]

        name   = decrypt_name(name_raw)
        size   = size_enc ^ KEY_SIZE
        offset = off_enc  ^ KEY_OFFSET

        entries.append((name, offset, size))

    # Sanity check
    filesize = len(data)
    expected_data_start = 4 + count * ENTRY_SIZE
    for i, (n, o, s) in enumerate(entries):
        if o + s > filesize:
            raise ValueError(f"Entry {i} ({n}) exceeds file: off=0x{o:X}, size=0x{s:X}, fs=0x{filesize:X}")
        if o < expected_data_start:
            raise ValueError(f"Entry {i} ({n}) overlaps index: off=0x{o:X}")

    return data, entries


def cmd_list(arc_path: str):
    """列出 ARC 内容"""
    _, entries = parse_arc(arc_path)
    print(f"{'Index':>5}  {'Offset':>10}  {'Size':>10}  Name")
    print("-" * 60)
    for i, (name, offset, size) in enumerate(entries):
        print(f"{i:5d}  0x{offset:08X}  0x{size:08X}  {name}")
    print(f"\n[+] Total: {len(entries)} files")


def cmd_unpack(arc_path: str, out_dir: str):
    """解包 ARC 所有文件"""
    data, entries = parse_arc(arc_path)
    os.makedirs(out_dir, exist_ok=True)

    # 写 _order.txt 记录原文件顺序 (pack 时会自动读取, 保证顺序一致)
    with open(os.path.join(out_dir, '_order.txt'), 'w', encoding='utf-8') as f:
        for name, _, _ in entries:
            f.write(name + '\n')

    for i, (name, offset, size) in enumerate(entries):
        out_path = os.path.join(out_dir, name)
        with open(out_path, 'wb') as f:
            f.write(data[offset : offset + size])
        print(f"  [{i+1:3d}/{len(entries)}] {name} ({size} bytes)")

    print(f"\n[+] Unpacked {len(entries)} files to {out_dir}")
    print(f"[+] Wrote _order.txt ({len(entries)} entries)")


def cmd_pack(in_dir: str, arc_path: str):
    """打包目录为 ARC
    
    重要: 文件顺序必须与原 ARC 一致, 否则游戏可能按索引访问失败.
    建议先用 list 命令导出顺序, 或提供 order.txt 手动指定.
    """
    # Get all files (MES + LIB)
    all_files = []
    for fn in sorted(os.listdir(in_dir)):
        full = os.path.join(in_dir, fn)
        if os.path.isfile(full):
            all_files.append(fn)

    if not all_files:
        print("[-] No files found in input directory")
        return

    # Check for order.txt
    order_file = os.path.join(in_dir, '_order.txt')
    if os.path.exists(order_file):
        print(f"[+] Using order from {order_file}")
        with open(order_file, 'r', encoding='utf-8') as f:
            ordered_names = [line.strip() for line in f if line.strip()]
        # Verify all files exist
        existing = set(all_files)
        for n in ordered_names:
            if n not in existing:
                raise ValueError(f"File in order.txt not found: {n}")
        all_files = ordered_names
    else:
        # Default: sort, but report which files
        all_files = [f for f in all_files if f != '_order.txt']
        print(f"[!] No _order.txt found, using sorted order ({len(all_files)} files)")

    count = len(all_files)
    index_size = count * ENTRY_SIZE
    data_start = 4 + index_size

    # Build index + data
    index_bytes = bytearray()
    data_bytes  = bytearray()
    cursor = data_start

    for name in all_files:
        full = os.path.join(in_dir, name)
        with open(full, 'rb') as f:
            content = f.read()

        name_enc = encrypt_name(name.upper())  # AI5 默认大写
        size_enc = struct.pack('<I', len(content) ^ KEY_SIZE)
        off_enc  = struct.pack('<I', cursor ^ KEY_OFFSET)

        index_bytes += name_enc + size_enc + off_enc
        data_bytes  += content
        cursor += len(content)

    with open(arc_path, 'wb') as f:
        f.write(struct.pack('<I', count))
        f.write(bytes(index_bytes))
        f.write(bytes(data_bytes))

    print(f"[+] Packed {count} files -> {arc_path} ({cursor} bytes)")


def cmd_verify(arc_path: str):
    """Round-trip 验证: 解包 -> 重新打包 -> 比对"""
    import hashlib
    import tempfile
    import shutil

    print(f"[+] Original: {arc_path}")
    with open(arc_path, 'rb') as f:
        orig_md5 = hashlib.md5(f.read()).hexdigest()
    print(f"    MD5: {orig_md5}")

    with tempfile.TemporaryDirectory() as tmp:
        extract_dir = os.path.join(tmp, 'extracted')
        repack_path = os.path.join(tmp, 'repack.arc')

        # Unpack
        data, entries = parse_arc(arc_path)
        os.makedirs(extract_dir, exist_ok=True)
        with open(os.path.join(extract_dir, '_order.txt'), 'w', encoding='utf-8') as f:
            for name, _, _ in entries:
                f.write(name + '\n')
        for name, offset, size in entries:
            with open(os.path.join(extract_dir, name), 'wb') as f:
                f.write(data[offset:offset + size])
        print(f"    Extracted {len(entries)} files")

        # Repack
        cmd_pack(extract_dir, repack_path)

        with open(repack_path, 'rb') as f:
            new_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"    Repack MD5: {new_md5}")

        if orig_md5 == new_md5:
            print("[+] ROUND-TRIP SUCCESS: byte-identical")
        else:
            print("[-] ROUND-TRIP FAIL: files differ")
            # Diff
            with open(arc_path, 'rb') as f:
                orig = f.read()
            with open(repack_path, 'rb') as f:
                new = f.read()
            if len(orig) != len(new):
                print(f"    Size mismatch: {len(orig)} vs {len(new)}")
            else:
                diffs = [i for i in range(len(orig)) if orig[i] != new[i]]
                print(f"    Differing bytes: {len(diffs)}, first at 0x{diffs[0]:X}" if diffs else "    (no byte diff??)")


def main():
    ap = argparse.ArgumentParser(description='AI5WIN V6 ARC tool')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_list = sub.add_parser('list', help='List ARC contents')
    p_list.add_argument('arc')

    p_unpack = sub.add_parser('unpack', help='Unpack ARC')
    p_unpack.add_argument('arc')
    p_unpack.add_argument('out_dir')

    p_pack = sub.add_parser('pack', help='Pack directory to ARC')
    p_pack.add_argument('in_dir')
    p_pack.add_argument('arc')

    p_verify = sub.add_parser('verify', help='Round-trip verify')
    p_verify.add_argument('arc')

    args = ap.parse_args()

    if args.cmd == 'list':
        cmd_list(args.arc)
    elif args.cmd == 'unpack':
        cmd_unpack(args.arc, args.out_dir)
    elif args.cmd == 'pack':
        cmd_pack(args.in_dir, args.arc)
    elif args.cmd == 'verify':
        cmd_verify(args.arc)


if __name__ == '__main__':
    main()
