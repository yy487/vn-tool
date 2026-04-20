#!/usr/bin/env python3
"""
mrg_unpack.py - ADVWIN32 / F&C Co. MRG archive unpacker
Engine: ADVWIN32 (木漏れ日の並木道 etc.)

MRG format:
  Header (0x10 bytes):
    0x00: 'MRG\x00' signature
    0x04: key1index (u16)
    0x06: key2index (u16) - if <2: v1 format, >=2: v2 format
    0x08: index_end_offset (u32) - byte offset where file data begins
    0x0C: file_count (u32)

  Encrypted directory (index_end - 0x10 bytes):
    Entry format (v1, 0x20 bytes each, but (count+1) offsets stored):
      0x00: filename (0x0E bytes, null-terminated)
      0x0E: unpacked_size (u32)
      0x12: method (u8) - 0=raw/encrypted, 1=LZSS, 2=MrgDecoder, 3=MrgDecoder+LZSS
      0x1C: next_entry_offset (u32)
    Key guessed from last 4 bytes of directory = file_size

  Decryption: ROL(byte,1) ^ key, key += remaining_length (decreasing)

  LZSS (method 1/3): 4KB window, init pos 0xFEE, flag LSB-first

Usage:
    python mrg_unpack.py <archive.mrg> [output_dir]
    python mrg_unpack.py -l <archive.mrg>          # list only
    python mrg_unpack.py -b <directory>             # batch unpack all MRG files
"""

import struct, sys, os, argparse
from pathlib import Path


def rol1(b):
    return ((b << 1) | (b >> 7)) & 0xFF


def mrg_decrypt(data, key):
    """Decrypt MRG directory or method=0 file data."""
    result = bytearray(len(data))
    length = len(data)
    for i in range(length):
        result[i] = rol1(data[i]) ^ (key & 0xFF)
        key = (key + length) & 0xFF
        length -= 1
    return result


def mrg_guess_key(index, file_size):
    """
    Guess decryption key using known-plaintext: last 4 bytes of decrypted
    directory must equal file_size (little-endian).
    """
    actual = file_size
    v = rol1(index[-1])
    key = v ^ ((actual >> 24) & 0xFF)

    remaining = 1
    last_offset = v ^ key
    for i in range(len(index) - 2, len(index) - 5, -1):
        remaining += 1
        key = (key - remaining) & 0xFF
        v = rol1(index[i])
        last_offset = (last_offset << 8) | (v ^ key)

    if last_offset != actual:
        return None

    # Rewind key to index[0]
    while remaining < len(index):
        remaining += 1
        key = (key - remaining) & 0xFF

    return key


def lzss_decompress(src_bytes, max_output):
    """LZSS: 4KB window, init pos 0xFEE, flag LSB-first."""
    src = src_bytes if isinstance(src_bytes, (bytes, bytearray)) else bytes(src_bytes)
    window = bytearray(4096)
    wpos = 0xFEE
    out = bytearray()
    si = 0
    end = len(src)
    while si < end and len(out) < max_output:
        flags = src[si] | 0xFF00
        si += 1
        while flags & 0x100:
            if si >= end or len(out) >= max_output:
                return out
            if flags & 1:
                b = src[si]; si += 1
                window[wpos & 0xFFF] = b
                wpos += 1
                out.append(b)
            else:
                if si + 1 >= end:
                    return out
                # GARbro: offset = ReadUInt16(), count = (offset >> 12) + 3, offset &= 0xFFF
                raw = src[si] | (src[si + 1] << 8)
                si += 2
                offset = raw & 0xFFF
                count = (raw >> 12) + 3
                for _ in range(count):
                    if len(out) >= max_output:
                        return out
                    b = window[offset & 0xFFF]
                    offset += 1
                    window[wpos & 0xFFF] = b
                    wpos += 1
                    out.append(b)
            flags >>= 1
    return out


def mrg_open(filepath):
    """Parse MRG archive, return list of (name, offset, size, unpacked_size, method)."""
    with open(filepath, 'rb') as f:
        data = f.read()

    if data[:4] != b'MRG\x00':
        raise ValueError("Not a MRG archive")

    key1idx = struct.unpack_from('<H', data, 4)[0]
    key2idx = struct.unpack_from('<H', data, 6)[0]
    index_end = struct.unpack_from('<I', data, 8)[0]
    file_count = struct.unpack_from('<I', data, 12)[0]

    if key2idx >= 2:
        raise ValueError("MRG v2+ format not supported (use GARbro)")

    index_size = index_end - 0x10
    if index_size < 0x20 or index_end > len(data):
        raise ValueError("Invalid index size")

    index = bytearray(data[0x10:index_end])
    file_size = len(data)

    key = mrg_guess_key(index, file_size)
    if key is None:
        raise ValueError("Failed to guess decryption key")

    dec_index = mrg_decrypt(index, key)

    entries = []
    current = 0
    next_offset = struct.unpack_from('<I', dec_index, current + 0x1C)[0]

    for i in range(file_count):
        name_raw = dec_index[current:current + 0x0E]
        name_end = name_raw.find(b'\x00')
        if name_end < 0:
            name_end = 0x0E
        name = name_raw[:name_end].decode('ascii', errors='replace')

        unpacked_size = struct.unpack_from('<I', dec_index, current + 0x0E)[0]
        method = dec_index[current + 0x12]

        entry_offset = next_offset
        if current + 0x3C < len(dec_index):
            next_offset = struct.unpack_from('<I', dec_index, current + 0x3C)[0]
        else:
            next_offset = file_size
        entry_size = next_offset - entry_offset

        entries.append({
            'name': name,
            'offset': entry_offset,
            'size': entry_size,
            'unpacked_size': unpacked_size,
            'method': method,
        })
        current += 0x20

    return data, entries, key


def extract_entry(data, entry):
    """Extract and decompress a single entry."""
    raw = data[entry['offset']:entry['offset'] + entry['size']]
    method = entry['method']

    if method == 0:
        return raw
    elif method == 1:
        return bytes(lzss_decompress(raw, entry['unpacked_size']))
    elif method >= 2:
        print(f"    WARNING: method {method} (MrgDecoder) not implemented, extracting raw")
        return raw
    return raw


def list_archive(filepath):
    """List contents of MRG archive."""
    data, entries, key = mrg_open(filepath)
    print(f"Archive: {filepath}")
    print(f"Key: 0x{key:02X}, Files: {len(entries)}")
    print(f"{'#':>3}  {'Name':<24} {'Offset':>10} {'Size':>10} {'Unpacked':>10} {'Method':>6}")
    print("-" * 70)
    for i, e in enumerate(entries):
        print(f"{i:3d}  {e['name']:<24} 0x{e['offset']:08X} {e['size']:10d} {e['unpacked_size']:10d} {e['method']:6d}")


def unpack_archive(filepath, output_dir=None):
    """Extract all files from MRG archive."""
    data, entries, key = mrg_open(filepath)
    basename = Path(filepath).stem
    if output_dir is None:
        output_dir = basename

    os.makedirs(output_dir, exist_ok=True)
    print(f"Unpacking {filepath} -> {output_dir}/ (key=0x{key:02X}, {len(entries)} files)")

    for i, entry in enumerate(entries):
        try:
            extracted = extract_entry(data, entry)
            out_path = os.path.join(output_dir, entry['name'])
            with open(out_path, 'wb') as f:
                f.write(extracted)
            status = f"{len(extracted)} bytes"
            if entry['method'] == 1:
                status += " (LZSS)"
            print(f"  [{i}] {entry['name']} - {status}")
        except Exception as e:
            print(f"  [{i}] {entry['name']} - ERROR: {e}")


def batch_unpack(directory):
    """Unpack all MRG files in directory."""
    mrg_files = sorted(Path(directory).glob('*.[Mm][Rr][Gg]'))
    if not mrg_files:
        print(f"No MRG files found in {directory}")
        return
    for f in mrg_files:
        try:
            unpack_archive(str(f), str(f.parent / f.stem))
        except Exception as e:
            print(f"  {f.name}: ERROR - {e}")
        print()


def main():
    ap = argparse.ArgumentParser(description='ADVWIN32 MRG archive unpacker')
    ap.add_argument('input', nargs='?', help='Input MRG file or directory (with -b)')
    ap.add_argument('output', nargs='?', help='Output directory')
    ap.add_argument('-l', '--list', action='store_true', help='List archive contents')
    ap.add_argument('-b', '--batch', action='store_true', help='Batch unpack all MRG files')
    a = ap.parse_args()

    if not a.input:
        ap.print_help()
        return

    if a.batch:
        batch_unpack(a.input)
    elif a.list:
        list_archive(a.input)
    else:
        unpack_archive(a.input, a.output)


if __name__ == '__main__':
    main()
