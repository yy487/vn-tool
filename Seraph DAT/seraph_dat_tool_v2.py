#!/usr/bin/env python3
"""
Seraph Engine - ArchPac.dat Unpacker v2
Supports automatic index_offset detection from ScnPac.Dat

ArchPac index format (at index_offset):
  [ncat:u32]            - number of categories
  [total:u32]           - total file count
  ncat × [base:u32][count:u32]  - per-category base offset and file count
  Reverse-order sub-offset table:
    For each category (from ncat-1 down to 0):
      (count+1) × u32 sub-offsets
    Entry[i].offset = base[cat] + sub_off[i]
    Entry[i].size = sub_off[i+1] - sub_off[i]

index_offset is stored in ScnPac.Dat script bytecode as:
  opcode 0x16, then RPN expression: 0x05 [u32_le] 0xFF
"""

import struct
import sys
import os
import argparse
from pathlib import Path


def find_index_offset_from_scnpac(scnpac_path: str) -> int | None:
    """
    Search ScnPac.Dat for the ArchPac index_offset.
    Pattern: opcode 0x16 followed by 0x05 [u32_le] 0xFF in script bytecode.
    """
    with open(scnpac_path, 'rb') as f:
        raw = f.read()
    
    count = struct.unpack_from('<I', raw, 0)[0]
    offsets = [struct.unpack_from('<I', raw, 4 + i * 4)[0] for i in range(count + 1)]
    
    candidates = []
    for idx in range(count):
        s_start = offsets[idx]
        s_end = offsets[idx + 1]
        script = raw[s_start:s_end]
        
        for j in range(len(script) - 7):
            if script[j] == 0x16 and script[j+1] == 0x05 and script[j+6] == 0xFF:
                val = struct.unpack_from('<I', script, j + 2)[0]
                candidates.append((idx, j, val))
    
    if not candidates:
        # Fallback: search for 0x05 [large_u32] 0xFF without preceding 0x16
        for idx in range(count):
            s_start = offsets[idx]
            s_end = offsets[idx + 1]
            script = raw[s_start:s_end]
            for j in range(len(script) - 6):
                if script[j] == 0x05 and script[j+5] == 0xFF:
                    val = struct.unpack_from('<I', script, j + 1)[0]
                    if val > 0x100000:  # > 1MB, likely an offset
                        candidates.append((idx, j, val))
    
    if not candidates:
        return None
    
    if len(candidates) == 1:
        return candidates[0][2]
    
    # If multiple, prefer the one with opcode 0x16 prefix, or the largest value
    # (ArchPac index is usually near the end of the file)
    print(f"Found {len(candidates)} candidate(s):")
    for idx, pos, val in candidates:
        print(f"  Script {idx} +{pos}: 0x{val:X} ({val:,})")
    
    # Return the one most likely to be the ArchPac index offset
    # Heuristic: 0x16 prefix candidates first, then largest value
    return candidates[0][2]


def parse_archpac_index(data: bytes, index_offset: int, verbose: bool = False):
    """
    Parse ArchPac.dat index at the given offset.
    Returns list of (offset, size) tuples.
    """
    pos = index_offset
    
    ncat = struct.unpack_from('<I', data, pos)[0]
    total = struct.unpack_from('<I', data, pos + 4)[0]
    pos += 8
    
    if verbose:
        print(f"  ncat = {ncat}")
        print(f"  total = {total}")
    
    if ncat > 64 or total > 100000:
        raise ValueError(f"Suspicious index header: ncat={ncat}, total={total}")
    
    # Read per-category (base, count)
    categories = []
    for i in range(ncat):
        base = struct.unpack_from('<I', data, pos)[0]
        cnt = struct.unpack_from('<I', data, pos + 4)[0]
        categories.append((base, cnt))
        pos += 8
    
    if verbose:
        for i, (b, c) in enumerate(categories):
            print(f"  cat[{i}]: base=0x{b:08X} count={c}")
    
    # Verify total matches sum of counts
    sum_counts = sum(c for _, c in categories)
    if sum_counts != total:
        raise ValueError(f"Count mismatch: sum={sum_counts}, total={total}")
    
    # Read sub-offset tables (reverse category order)
    entries = [None] * total
    global_idx = 0
    
    for cat_idx in range(ncat - 1, -1, -1):
        base, cnt = categories[cat_idx]
        
        # Read first sub-offset
        prev_sub = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        
        if verbose and cnt > 0:
            print(f"  cat[{cat_idx}] first_sub=0x{prev_sub:X}, reading {cnt} entries from pos=0x{pos:X}")
        
        for j in range(cnt):
            entry_offset = base + prev_sub
            
            # Read next sub-offset
            next_sub = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            
            entry_size = next_sub - prev_sub
            
            entries[global_idx] = (entry_offset, entry_size)
            global_idx += 1
            prev_sub = next_sub
    
    if verbose:
        print(f"  Index data consumed: 0x{pos - index_offset:X} bytes (end pos=0x{pos:X})")
    
    return entries


def unpack_archpac(archpac_path: str, output_dir: str, index_offset: int, 
                   list_only: bool = False, verify: bool = False):
    """Unpack ArchPac.dat using the given index_offset."""
    
    with open(archpac_path, 'rb') as f:
        data = f.read()
    
    file_size = len(data)
    print(f"ArchPac: {file_size:,} bytes")
    print(f"Index offset: 0x{index_offset:X} ({index_offset:,})")
    
    if index_offset >= file_size:
        print(f"ERROR: index_offset (0x{index_offset:X}) >= file_size (0x{file_size:X})")
        return
    
    entries = parse_archpac_index(data, index_offset, verbose=(verify or list_only))
    print(f"Files: {len(entries)}")
    print()
    
    if list_only:
        for i, (off, sz) in enumerate(entries):
            # Try to identify file type from magic bytes
            magic = ""
            if off + 2 <= file_size:
                sig = data[off:off+2]
                if sig in (b'CF', b'CT', b'CC', b'CB', b'BM'):
                    magic = f" [{sig.decode('ascii')}]"
                elif data[off:off+4] == b'RIFF':
                    magic = " [WAV]"
            
            valid = "OK" if off + sz <= file_size else "OVERFLOW"
            print(f"  {i:4d}: offset=0x{off:08X} size={sz:>10,}{magic}  {valid}")
        return
    
    if verify:
        ok = 0
        bad = 0
        bad_reasons = {'overflow': 0, 'negative_size': 0, 'zero_size': 0}
        first_bad = []
        for i, (off, sz) in enumerate(entries):
            if sz > 0x7FFFFFFF:  # likely negative (unsigned interpretation)
                bad += 1
                bad_reasons['negative_size'] += 1
                if len(first_bad) < 5:
                    first_bad.append((i, off, sz, 'NEG_SIZE'))
            elif sz == 0:
                bad += 1
                bad_reasons['zero_size'] += 1
            elif off + sz > file_size:
                bad += 1
                bad_reasons['overflow'] += 1
                if len(first_bad) < 5:
                    first_bad.append((i, off, sz, 'OVERFLOW'))
            else:
                ok += 1
        
        print(f"Verify: {ok} OK, {bad} BAD out of {len(entries)}")
        if bad > 0:
            print(f"  Breakdown: {bad_reasons}")
            for i, off, sz, reason in first_bad:
                print(f"  BAD #{i:4d}: offset=0x{off:08X} size=0x{sz:08X} ({sz:>12,}) [{reason}]")
        
        # Show first OK entry for comparison
        for i, (off, sz) in enumerate(entries):
            if 0 < sz <= file_size and off + sz <= file_size:
                sig = data[off:off+4] if off + 4 <= file_size else b''
                print(f"  First OK #{i:4d}: offset=0x{off:08X} size={sz:>10,} sig={sig[:4]}")
                break
        # Show boundary between OK and BAD
        prev_ok = True
        for i, (off, sz) in enumerate(entries):
            is_ok = (0 < sz <= file_size and off + sz <= file_size)
            if prev_ok and not is_ok and i > 0:
                print(f"  First BAD transition at #{i}: offset=0x{off:08X} size=0x{sz:08X}")
                if i > 0:
                    po, ps = entries[i-1]
                    print(f"  Previous OK #{i-1}: offset=0x{po:08X} size={ps:>10,}")
                break
            prev_ok = is_ok
        return
    
    # Extract files
    os.makedirs(output_dir, exist_ok=True)
    
    ext_map = {b'CF': '.cf', b'CT': '.ct', b'CC': '.cc', b'CB': '.cb', b'BM': '.bmp'}
    
    success = 0
    for i, (off, sz) in enumerate(entries):
        if sz <= 0 or off + sz > file_size:
            print(f"  SKIP {i:4d}: invalid offset/size")
            continue
        
        file_data = data[off:off + sz]
        
        # Determine extension
        sig = file_data[:2] if len(file_data) >= 2 else b''
        ext = ext_map.get(sig, '.bin')
        if file_data[:4] == b'RIFF':
            ext = '.wav'
        
        out_path = os.path.join(output_dir, f"{i:04d}{ext}")
        with open(out_path, 'wb') as f:
            f.write(file_data)
        success += 1
    
    print(f"Extracted: {success}/{len(entries)} files to {output_dir}/")


def main():
    parser = argparse.ArgumentParser(description='Seraph Engine ArchPac.dat Unpacker v2')
    parser.add_argument('archpac', help='Path to ArchPac.dat')
    parser.add_argument('output', nargs='?', default=None, help='Output directory')
    parser.add_argument('-i', '--index-offset', type=lambda x: int(x, 0),
                        help='Index offset (hex or decimal). Auto-detected from ScnPac if not given.')
    parser.add_argument('-s', '--scnpac', default=None,
                        help='Path to ScnPac.Dat for auto-detecting index_offset')
    parser.add_argument('-l', '--list', action='store_true', help='List files only')
    parser.add_argument('-v', '--verify', action='store_true', help='Verify index integrity')
    args = parser.parse_args()
    
    # Determine index_offset
    if args.index_offset is not None:
        index_offset = args.index_offset
        print(f"Using specified index_offset: 0x{index_offset:X}")
    elif args.scnpac:
        print(f"Auto-detecting index_offset from {args.scnpac}...")
        index_offset = find_index_offset_from_scnpac(args.scnpac)
        if index_offset is None:
            print("ERROR: Could not find index_offset in ScnPac.Dat")
            sys.exit(1)
        print(f"Detected index_offset: 0x{index_offset:X}")
    else:
        # Try to find ScnPac.Dat in the same directory
        archpac_dir = os.path.dirname(os.path.abspath(args.archpac))
        scnpac_candidates = ['ScnPac.Dat', 'scnpac.dat', 'ScnPac.dat', 'SCNPAC.DAT']
        scnpac_path = None
        for name in scnpac_candidates:
            p = os.path.join(archpac_dir, name)
            if os.path.exists(p):
                scnpac_path = p
                break
        
        if scnpac_path:
            print(f"Auto-detecting index_offset from {scnpac_path}...")
            index_offset = find_index_offset_from_scnpac(scnpac_path)
            if index_offset is None:
                print("ERROR: Could not find index_offset. Use -i to specify manually.")
                sys.exit(1)
            print(f"Detected index_offset: 0x{index_offset:X}")
        else:
            print("ERROR: No ScnPac.Dat found. Use -s or -i to specify index_offset.")
            sys.exit(1)
    
    if args.list:
        unpack_archpac(args.archpac, '', index_offset, list_only=True)
    elif args.verify:
        unpack_archpac(args.archpac, '', index_offset, verify=True)
    else:
        output = args.output or 'out_arch'
        unpack_archpac(args.archpac, output, index_offset)


if __name__ == '__main__':
    main()
