#!/usr/bin/env python3
"""
mrg_tool.py - F&C Co. MRG archive unpack/repack tool
Engine: ADVWIN32 (F&C Co., Ltd.)
Format: MRG v1 (index encrypted with ROL1+XOR stream cipher, data LZSS compressed)

Usage:
    python mrg_tool.py unpack  ECHO_MES.MRG -o output_dir/
    python mrg_tool.py repack  output_dir/ -o ECHO_MES_NEW.MRG
    python mrg_tool.py list    ECHO_MES.MRG

Round-trip verified: unpack -> repack -> unpack -> diff = 0 mismatch
"""

import struct
import json
import sys
import os
import argparse
from pathlib import Path


# ============================================================
#  Constants
# ============================================================

MRG_MAGIC = 0x0047524D   # 'MRG\0'
HEADER_SIZE = 0x10
ENTRY_SIZE  = 0x20        # 32 bytes per index entry
LZSS_FRAME_SIZE = 0x1000
LZSS_FRAME_INIT_POS = 0xFEE
LZSS_FRAME_FILL = 0x20   # Original engine uses space fill; GARbro uses 0x00 (bug)


# ============================================================
#  Crypto: ROL1 + XOR stream cipher
# ============================================================

def _rol1(v: int) -> int:
    return ((v << 1) | (v >> 7)) & 0xFF

def _ror1(v: int) -> int:
    return ((v >> 1) | (v << 7)) & 0xFF

def decrypt_index(buf: bytes, key: int) -> bytearray:
    result = bytearray(len(buf))
    length = len(buf)
    k = key & 0xFF
    for i in range(length):
        result[i] = (_rol1(buf[i]) ^ k) & 0xFF
        k = (k + length) & 0xFF
        length -= 1
    return result

def encrypt_index(buf: bytes, key: int) -> bytearray:
    result = bytearray(len(buf))
    length = len(buf)
    k = key & 0xFF
    for i in range(length):
        result[i] = _ror1((buf[i] ^ k) & 0xFF)
        k = (k + length) & 0xFF
        length -= 1
    return result

def guess_key(index_raw: bytes, file_size: int) -> int:
    n = len(index_raw)
    actual = file_size
    v = _rol1(index_raw[n - 1])
    key = (v ^ ((actual >> 24) & 0xFF)) & 0xFF
    remaining = 1
    last_offset = (v ^ key) & 0xFF
    for i in range(n - 2, n - 4 - 1, -1):
        remaining += 1
        key = (key - remaining) & 0xFF
        v = _rol1(index_raw[i])
        last_offset = (last_offset << 8) | (v ^ key)
    if last_offset != actual:
        raise ValueError(
            f"Key guess failed: got 0x{last_offset:08X}, expected 0x{actual:08X}"
        )
    while remaining < n:
        remaining += 1
        key = (key - remaining) & 0xFF
    return key & 0xFF


# ============================================================
#  LZSS
# ============================================================

def lzss_decompress(src: bytes, unpacked_size: int) -> bytes:
    dst = bytearray()
    frame = bytearray([LZSS_FRAME_FILL] * LZSS_FRAME_SIZE)
    fpos = LZSS_FRAME_INIT_POS
    pos = 0
    remaining = len(src)
    while remaining > 0 and len(dst) < unpacked_size:
        ctl = src[pos]; pos += 1; remaining -= 1
        for bit in range(8):
            if remaining <= 0 or len(dst) >= unpacked_size:
                break
            if ctl & (1 << bit):
                b = src[pos]; pos += 1; remaining -= 1
                frame[fpos] = b
                fpos = (fpos + 1) & 0xFFF
                dst.append(b)
            else:
                if remaining < 2:
                    break
                val = src[pos] | (src[pos + 1] << 8)
                pos += 2; remaining -= 2
                offset = val & 0xFFF
                count = (val >> 12) + 3
                for _ in range(count):
                    if len(dst) >= unpacked_size:
                        break
                    v = frame[offset & 0xFFF]
                    offset += 1
                    frame[fpos] = v
                    fpos = (fpos + 1) & 0xFFF
                    dst.append(v)
    return bytes(dst)

def lzss_compress_literal(src: bytes) -> bytes:
    """Pure literal LZSS: ctl=0xFF, 8 bytes per group. +12.5% overhead, 100% safe."""
    dst = bytearray()
    pos = 0
    while pos < len(src):
        chunk = min(8, len(src) - pos)
        dst.append((1 << chunk) - 1)
        dst.extend(src[pos:pos + chunk])
        pos += chunk
    return bytes(dst)


# ============================================================
#  MRG parsing
# ============================================================

def parse_mrg(filepath: str):
    with open(filepath, 'rb') as f:
        data = f.read()
    file_size = len(data)
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != MRG_MAGIC:
        raise ValueError(f"Not a MRG file: magic=0x{magic:08X}")
    key1_idx = struct.unpack_from('<H', data, 4)[0]
    key2_idx = struct.unpack_from('<H', data, 6)[0]
    data_offset = struct.unpack_from('<I', data, 8)[0]
    count = struct.unpack_from('<I', data, 12)[0]
    index_size = data_offset - HEADER_SIZE
    if index_size != (count + 1) * ENTRY_SIZE:
        raise ValueError(f"Index size mismatch")
    index_raw = data[HEADER_SIZE : HEADER_SIZE + index_size]
    key = guess_key(index_raw, file_size)
    index = decrypt_index(index_raw, key)
    entries = []
    next_offset = struct.unpack_from('<I', index, 0x1C)[0]
    for i in range(count):
        off = i * ENTRY_SIZE
        name_raw = index[off : off + 0x0E]
        try:
            null_pos = name_raw.index(0)
            name = name_raw[:null_pos].decode('ascii')
        except (ValueError, UnicodeDecodeError):
            name = name_raw.decode('ascii', errors='replace').rstrip('\x00')
        unpacked_size = struct.unpack_from('<I', index, off + 0x0E)[0]
        method = index[off + 0x12]
        entry_offset = next_offset
        next_offset = struct.unpack_from('<I', index, (i + 1) * ENTRY_SIZE + 0x1C)[0]
        entry_size = next_offset - entry_offset
        entries.append({
            'index': i,
            'name': name,
            'offset': entry_offset,
            'size': entry_size,
            'unpacked_size': unpacked_size,
            'method': method,
        })
    header_info = {
        'key1_index': key1_idx,
        'key2_index': key2_idx,
        'data_offset': data_offset,
        'entry_count': count,
        'key': key,
    }
    return data, header_info, entries


# ============================================================
#  Commands
# ============================================================

def cmd_unpack(args):
    filepath = args.input
    outdir = args.output or (Path(filepath).stem + '_unpacked')
    os.makedirs(outdir, exist_ok=True)
    data, header, entries = parse_mrg(filepath)
    print(f"MRG: {filepath}")
    print(f"  Entries: {header['entry_count']}, Key: 0x{header['key']:02X}")
    print()
    for e in entries:
        raw = data[e['offset'] : e['offset'] + e['size']]
        if e['method'] == 0:
            content = raw
        elif e['method'] == 1:
            content = lzss_decompress(raw, e['unpacked_size'])
        else:
            print(f"  WARNING: {e['name']} method={e['method']} (unsupported), saving raw")
            content = raw
        outpath = os.path.join(outdir, e['name'])
        with open(outpath, 'wb') as f:
            f.write(content)
    meta = {
        'source': os.path.basename(filepath),
        'header': header,
        'entries': [{'name': e['name'], 'method': e['method']} for e in entries],
    }
    with open(os.path.join(outdir, '_mrg_meta.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"Unpacked {len(entries)} files to {outdir}/")


def cmd_repack(args):
    indir = args.input
    meta_path = os.path.join(indir, '_mrg_meta.json')
    if not os.path.exists(meta_path):
        print(f"ERROR: {meta_path} not found.", file=sys.stderr)
        sys.exit(1)
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    header = meta['header']
    entry_metas = meta['entries']
    count = len(entry_metas)
    key = header['key']

    file_data = []
    for em in entry_metas:
        with open(os.path.join(indir, em['name']), 'rb') as f:
            file_data.append(f.read())

    compressed = []
    for content, em in zip(file_data, entry_metas):
        if em['method'] == 0:
            compressed.append(content)
        elif em['method'] == 1:
            compressed.append(lzss_compress_literal(content))
        else:
            compressed.append(content)

    index_size = (count + 1) * ENTRY_SIZE
    data_start = HEADER_SIZE + index_size
    index = bytearray(index_size)
    offset = data_start

    for i in range(count):
        off = i * ENTRY_SIZE
        name_bytes = entry_metas[i]['name'].encode('ascii')[:0x0E]
        index[off : off + len(name_bytes)] = name_bytes
        struct.pack_into('<I', index, off + 0x0E, len(file_data[i]))
        index[off + 0x12] = entry_metas[i]['method']
        struct.pack_into('<I', index, off + 0x1C, offset)
        offset += len(compressed[i])

    struct.pack_into('<I', index, count * ENTRY_SIZE + 0x1C, offset)
    total_size = offset

    encrypted_index = encrypt_index(bytes(index), key)
    verify = decrypt_index(encrypted_index, key)
    assert verify == index, "Index encryption round-trip FAILED"

    header_buf = bytearray(HEADER_SIZE)
    struct.pack_into('<I', header_buf, 0, MRG_MAGIC)
    struct.pack_into('<H', header_buf, 4, header['key1_index'])
    struct.pack_into('<H', header_buf, 6, header['key2_index'])
    struct.pack_into('<I', header_buf, 8, data_start)
    struct.pack_into('<I', header_buf, 12, count)

    outpath = args.output or meta['source'].replace('.MRG', '_NEW.MRG')
    with open(outpath, 'wb') as f:
        f.write(header_buf)
        f.write(encrypted_index)
        for c in compressed:
            f.write(c)

    print(f"Repacked {count} files to {outpath} ({total_size:,} bytes)")


def cmd_list(args):
    _, header, entries = parse_mrg(args.input)
    print(f"MRG: {args.input}  |  {header['entry_count']} entries  |  Key: 0x{header['key']:02X}")
    print(f"{'#':>4s}  {'Name':20s}  {'Offset':>10s}  {'CompSize':>10s}  "
          f"{'UnpSize':>10s}  {'M':>1s}  {'Ratio':>6s}")
    print('-' * 76)
    for e in entries:
        r = e['size'] / e['unpacked_size'] * 100 if e['unpacked_size'] > 0 else 0
        print(f"{e['index']:4d}  {e['name']:20s}  0x{e['offset']:08X}  "
              f"{e['size']:10,d}  {e['unpacked_size']:10,d}  {e['method']:1d}  {r:5.1f}%")


def main():
    parser = argparse.ArgumentParser(description='F&C Co. MRG archive tool')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('unpack', help='Unpack MRG archive')
    p.add_argument('input'); p.add_argument('-o', '--output')
    p = sub.add_parser('repack', help='Repack into MRG')
    p.add_argument('input'); p.add_argument('-o', '--output')
    p = sub.add_parser('list', help='List contents')
    p.add_argument('input')
    args = parser.parse_args()
    {'unpack': cmd_unpack, 'repack': cmd_repack, 'list': cmd_list}[args.command](args)

if __name__ == '__main__':
    main()
