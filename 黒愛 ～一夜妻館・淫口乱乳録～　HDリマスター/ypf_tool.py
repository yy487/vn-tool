#!/usr/bin/env python3
"""
YU-RIS YPF Archive Tool
解包/封包工具 for YU-RIS engine YPF archives (黒愛 / KUROAI etc.)

Format:
  Header (0x20 bytes):
    @00: magic 'YPF\0'
    @04: version (u32)
    @08: entry_count (u32)
    @0C: index_size (u32, bytes after header)
    @10: padding (16 bytes zeros)
  
  Index (variable-length entries):
    hash (4B, CRC32 of filename)
    name_len_encoded (1B, swizzle table lookup)
    name (N bytes, ASCII)
    type (1B)
    compress_flag (1B, 1=zlib)
    decompressed_size (4B, u32 LE)
    compressed_size (4B, u32 LE)  
    file_offset (4B, u32 LE, absolute offset in archive)
  
  Data (zlib-compressed files at specified offsets)

Usage:
  python ypf_tool.py unpack   <archive.ypf> [output_dir]
  python ypf_tool.py repack   <input_dir> <output.ypf> [--version 0x8B]
  python ypf_tool.py list     <archive.ypf>
  python ypf_tool.py info     <archive.ypf>
"""

import struct
import zlib
import binascii
import os
import sys
import json
import argparse


# === Name length swizzle table ===
# YU-RIS uses a version-dependent lookup table for name_len encoding.
# Known mappings (version 0x8B): 0xE9->22, 0xEC->13, 0xED->18, 0xF0->15
# Since the full table is engine-internal, we use heuristic detection:
# scan for printable ASCII to determine actual name length.

# For repacking, we need the reverse mapping. We build it from known pairs
# and fall back to bitwise NOT (~len & 0xFF) for unknown lengths.
KNOWN_NAMELEN_ENCODE = {
    18: 0xED,
    13: 0xEC,
    22: 0xE9,
    15: 0xF0,
}


def encode_namelen(length):
    """Encode name length byte for index entry."""
    if length in KNOWN_NAMELEN_ENCODE:
        return KNOWN_NAMELEN_ENCODE[length]
    # Fallback: bitwise NOT (works for some versions)
    return (~length) & 0xFF


def parse_ypf(data):
    """Parse YPF archive, return (header_info, entries)."""
    if data[:4] != b'YPF\x00':
        raise ValueError("Not a YPF archive (bad magic)")
    
    version = struct.unpack_from('<I', data, 4)[0]
    entry_count = struct.unpack_from('<I', data, 8)[0]
    index_size = struct.unpack_from('<I', data, 0xC)[0]
    
    header_info = {
        'version': version,
        'entry_count': entry_count,
        'index_size': index_size,
    }
    
    entries = []
    offset = 0x20  # Header size
    
    for i in range(entry_count):
        if offset + 5 >= len(data):
            print(f"[WARN] Truncated index at entry {i}, offset {hex(offset)}")
            break
        
        entry_hash = struct.unpack_from('<I', data, offset)[0]
        raw_namelen = data[offset + 4]
        
        # Heuristic: scan for printable ASCII to find actual name length
        name_start = offset + 5
        j = name_start
        while j < min(name_start + 260, len(data)):
            b = data[j]
            if b < 0x20 or b > 0x7E:
                break
            j += 1
        
        name_len = j - name_start
        if name_len == 0:
            print(f"[WARN] Zero-length name at entry {i}, offset {hex(offset)}")
            break
        
        name = data[name_start:name_start + name_len].decode('ascii')
        
        field_offset = name_start + name_len
        if field_offset + 14 > len(data):
            print(f"[WARN] Truncated entry {i} at {hex(field_offset)}")
            break
        
        entry_type = data[field_offset]
        compress_flag = data[field_offset + 1]
        decomp_size = struct.unpack_from('<I', data, field_offset + 2)[0]
        comp_size = struct.unpack_from('<I', data, field_offset + 6)[0]
        file_offset = struct.unpack_from('<I', data, field_offset + 10)[0]
        
        entries.append({
            'name': name,
            'hash': entry_hash,
            'raw_namelen': raw_namelen,
            'type': entry_type,
            'compress': compress_flag,
            'decomp_size': decomp_size,
            'comp_size': comp_size,
            'offset': file_offset,
        })
        
        offset = field_offset + 14
    
    return header_info, entries


def unpack_ypf(ypf_path, output_dir):
    """Unpack YPF archive to output directory."""
    with open(ypf_path, 'rb') as f:
        data = f.read()
    
    header, entries = parse_ypf(data)
    
    print(f"YPF Archive: {ypf_path}")
    print(f"  Version: {header['version']:#x}")
    print(f"  Entries: {header['entry_count']}")
    print(f"  Index size: {header['index_size']:#x}")
    print()
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Save metadata for repacking
    meta = {
        'version': header['version'],
        'entries': []
    }
    
    ok = 0
    fail = 0
    
    for i, entry in enumerate(entries):
        name = entry['name']
        # Convert backslash paths to OS paths
        rel_path = name.replace('\\', os.sep)
        out_path = os.path.join(output_dir, rel_path)
        
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        
        try:
            comp_data = data[entry['offset']:entry['offset'] + entry['comp_size']]
            
            if entry['compress'] == 1 and entry['comp_size'] > 0:
                file_data = zlib.decompress(comp_data)
                if len(file_data) != entry['decomp_size']:
                    print(f"  [WARN] Size mismatch: {name} got {len(file_data)}, expected {entry['decomp_size']}")
            elif entry['compress'] == 0:
                file_data = comp_data
            else:
                # Unknown compression, try zlib first
                try:
                    file_data = zlib.decompress(comp_data)
                except:
                    file_data = comp_data
            
            with open(out_path, 'wb') as f:
                f.write(file_data)
            
            ok += 1
            
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            fail += 1
        
        meta['entries'].append({
            'name': name,
            'type': entry['type'],
            'compress': entry['compress'],
        })
    
    # Save metadata
    meta_path = os.path.join(output_dir, '__ypf_meta__.json')
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    
    print(f"Unpacked: {ok} OK, {fail} FAIL")
    print(f"Metadata saved to: {meta_path}")
    return ok, fail


def repack_ypf(input_dir, ypf_path, version=None):
    """Repack directory into YPF archive."""
    meta_path = os.path.join(input_dir, '__ypf_meta__.json')
    
    if os.path.exists(meta_path):
        with open(meta_path, 'r', encoding='utf-8') as f:
            meta = json.load(f)
        if version is None:
            version = meta.get('version', 0x8B)
        entry_metas = meta.get('entries', [])
    else:
        entry_metas = []
        if version is None:
            version = 0x8B
    
    # Collect files
    if entry_metas:
        # Use metadata order
        files = []
        for em in entry_metas:
            name = em['name']
            rel_path = name.replace('\\', os.sep)
            full_path = os.path.join(input_dir, rel_path)
            if os.path.exists(full_path):
                files.append({
                    'name': name,
                    'path': full_path,
                    'type': em.get('type', 3),
                    'compress': em.get('compress', 1),
                })
            else:
                print(f"[WARN] Missing file: {name}")
    else:
        # Scan directory
        files = []
        for root, dirs, filenames in os.walk(input_dir):
            for fn in sorted(filenames):
                if fn == '__ypf_meta__.json':
                    continue
                full_path = os.path.join(root, fn)
                rel = os.path.relpath(full_path, input_dir)
                name = rel.replace(os.sep, '\\')
                files.append({
                    'name': name,
                    'path': full_path,
                    'type': 3,
                    'compress': 1,
                })
    
    entry_count = len(files)
    print(f"Repacking {entry_count} files into {ypf_path}")
    print(f"  Version: {version:#x}")
    
    # Build index and compress data
    index_buf = bytearray()
    data_buf = bytearray()
    
    # Calculate index size first (need to know where data starts)
    # index entry = 4(hash) + 1(namelen) + N(name) + 1(type) + 1(comp) + 4(decomp) + 4(comp) + 4(offset)
    index_size = sum(4 + 1 + len(f['name'].encode('ascii')) + 1 + 1 + 4 + 4 + 4 for f in files)
    data_start = 0x20 + index_size
    
    current_data_offset = data_start
    
    for fi in files:
        name = fi['name']
        name_bytes = name.encode('ascii')
        
        with open(fi['path'], 'rb') as f:
            file_data = f.read()
        
        decomp_size = len(file_data)
        
        if fi['compress'] == 1:
            comp_data = zlib.compress(file_data)
        else:
            comp_data = file_data
        
        comp_size = len(comp_data)
        
        # Build entry
        entry_hash = binascii.crc32(name_bytes) & 0xFFFFFFFF
        namelen_enc = encode_namelen(len(name_bytes))
        
        index_buf += struct.pack('<I', entry_hash)
        index_buf += struct.pack('B', namelen_enc)
        index_buf += name_bytes
        index_buf += struct.pack('B', fi['type'])
        index_buf += struct.pack('B', fi['compress'])
        index_buf += struct.pack('<I', decomp_size)
        index_buf += struct.pack('<I', comp_size)
        index_buf += struct.pack('<I', current_data_offset)
        
        data_buf += comp_data
        current_data_offset += comp_size
    
    # Build header
    header = bytearray(0x20)
    header[0:4] = b'YPF\x00'
    struct.pack_into('<I', header, 4, version)
    struct.pack_into('<I', header, 8, entry_count)
    struct.pack_into('<I', header, 0xC, len(index_buf))
    
    with open(ypf_path, 'wb') as f:
        f.write(header)
        f.write(index_buf)
        f.write(data_buf)
    
    total_size = len(header) + len(index_buf) + len(data_buf)
    print(f"Written: {total_size} bytes ({total_size / 1024:.1f} KB)")
    return entry_count


def list_ypf(ypf_path):
    """List contents of YPF archive."""
    with open(ypf_path, 'rb') as f:
        data = f.read()
    
    header, entries = parse_ypf(data)
    
    print(f"{'#':>4s}  {'Name':<40s}  {'Decomp':>10s}  {'Comp':>10s}  {'Ratio':>6s}  {'Offset':>10s}  T  C")
    print('-' * 100)
    
    total_decomp = 0
    total_comp = 0
    
    for i, e in enumerate(entries):
        ratio = e['comp_size'] / e['decomp_size'] * 100 if e['decomp_size'] > 0 else 0
        total_decomp += e['decomp_size']
        total_comp += e['comp_size']
        print(f"{i:4d}  {e['name']:<40s}  {e['decomp_size']:>10d}  {e['comp_size']:>10d}  {ratio:5.1f}%  {e['offset']:#010x}  {e['type']}  {e['compress']}")
    
    print('-' * 100)
    overall = total_comp / total_decomp * 100 if total_decomp > 0 else 0
    print(f"Total: {len(entries)} files, {total_decomp} -> {total_comp} bytes ({overall:.1f}%)")


def info_ypf(ypf_path):
    """Show archive header info."""
    with open(ypf_path, 'rb') as f:
        data = f.read(0x20)
    
    if data[:4] != b'YPF\x00':
        print("Not a YPF archive")
        return
    
    version = struct.unpack_from('<I', data, 4)[0]
    count = struct.unpack_from('<I', data, 8)[0]
    idx_size = struct.unpack_from('<I', data, 0xC)[0]
    file_size = os.path.getsize(ypf_path)
    
    print(f"File: {ypf_path}")
    print(f"Size: {file_size} bytes ({file_size / 1024:.1f} KB)")
    print(f"Magic: YPF\\0")
    print(f"Version: {version:#x} ({version})")
    print(f"Entry count: {count}")
    print(f"Index size: {idx_size:#x} ({idx_size})")
    print(f"Data starts at: {0x20 + idx_size:#x}")


def main():
    parser = argparse.ArgumentParser(description='YU-RIS YPF Archive Tool')
    sub = parser.add_subparsers(dest='command')
    
    p_unpack = sub.add_parser('unpack', help='Unpack YPF archive')
    p_unpack.add_argument('archive', help='Input YPF file')
    p_unpack.add_argument('output', nargs='?', help='Output directory (default: archive name without extension)')
    
    p_repack = sub.add_parser('repack', help='Repack directory into YPF')
    p_repack.add_argument('input_dir', help='Input directory')
    p_repack.add_argument('output', help='Output YPF file')
    p_repack.add_argument('--version', type=lambda x: int(x, 0), default=None, help='Version field (default: from metadata or 0x8B)')
    
    p_list = sub.add_parser('list', help='List archive contents')
    p_list.add_argument('archive', help='YPF file')
    
    p_info = sub.add_parser('info', help='Show archive info')
    p_info.add_argument('archive', help='YPF file')
    
    args = parser.parse_args()
    
    if args.command == 'unpack':
        output = args.output
        if output is None:
            output = os.path.splitext(args.archive)[0]
        unpack_ypf(args.archive, output)
    
    elif args.command == 'repack':
        repack_ypf(args.input_dir, args.output, version=args.version)
    
    elif args.command == 'list':
        list_ypf(args.archive)
    
    elif args.command == 'info':
        info_ypf(args.archive)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
