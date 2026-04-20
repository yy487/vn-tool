#!/usr/bin/env python3
"""
月下の契り (Tsuki no Chigiri) SSB Script Text Tool
Engine: SAISYS (栈式VM, CODE.SSB + DATA.SSB)

Usage:
  python ssb_text.py extract CODE.SSB DATA.SSB [-o output.json]
  python ssb_text.py inject  CODE.SSB DATA.SSB input.json [-o out_dir] [-e gbk]

DATA.SSB: XOR 0xAA encrypted, flat byte array used as uint32-indexed variable/string storage
CODE.SSB: uint32 LE instruction stream (bit31=0: push literal, bit31=1: opcode)

Text display: 8 args pushed then CALL to subroutine 0xA9F7
  args: [0, speaker_idx, 0, line_count, text1_idx, text2_idx, 0x11, label_idx]
  text1 == text2 (identical copies for display / backlog)
  speaker name ends with \\r (0x0D)
  strings are null-terminated, 4-byte aligned in DATA.SSB

Inject strategy (full rebuild):
  - Keep DATA.SSB pre-text area (variables, 0x00000~text_start) unchanged
  - Rebuild ALL strings in text area + post-text area sequentially
  - Build old_idx -> new_idx mapping, patch ALL references in CODE.SSB
  - Total: ~25,027 CODE patches across 23,861 unique indices
"""

import struct
import json
import sys
import os
import argparse
from collections import OrderedDict


# === Constants ===
XOR_KEY = 0xAA
TEXT_CALL_TARGET = 0xA9F7
TEXT_START_IDX = 0x748B8
TEXT_END_IDX   = 0xA4B30
OPCODE_MASK    = 0x80000000
OP_CALL        = 0x8000000C
READ_ENCODING  = 'cp932'


def decode_data(raw: bytes) -> bytes:
    return bytes([b ^ XOR_KEY for b in raw])


def encode_data(decoded: bytes) -> bytes:
    return bytes([b ^ XOR_KEY for b in decoded])


def read_str_at(data: bytes, idx: int) -> bytes:
    """Read null-terminated bytes from DATA at uint32 index."""
    off = idx * 4
    if off >= len(data):
        return b''
    end = off
    while end < len(data) and data[end] != 0:
        end += 1
    return data[off:end]


def align4(size: int) -> int:
    return (size + 3) & ~3


def collect_text_entries(code: bytes) -> list:
    """Scan CODE.SSB for all text display calls (CALL 0xA9F7)."""
    n = len(code) // 4
    entries = []
    for i in range(n):
        val = struct.unpack_from('<I', code, i * 4)[0]
        if val != OP_CALL:
            continue
        if i < 1:
            continue
        target = struct.unpack_from('<I', code, (i - 1) * 4)[0]
        if target != TEXT_CALL_TARGET:
            continue
        args = [target]
        j = i - 2
        while j >= 0 and len(args) < 10:
            v = struct.unpack_from('<I', code, j * 4)[0]
            if v & OPCODE_MASK:
                break
            args.append(v)
            j -= 1
        args.reverse()
        if len(args) < 9:
            continue
        a = args[:-1]
        entries.append({
            'code_offset': i * 4,
            'arg0': a[0], 'speaker_idx': a[1], 'arg2': a[2],
            'lines': a[3], 'text1_idx': a[4], 'text2_idx': a[5],
            'flags': a[6], 'label_idx': a[7],
        })
    return entries


def collect_indices(code: bytes, start: int, end: int) -> set:
    """Collect all uint32 literals in CODE within [start, end)."""
    n = len(code) // 4
    result = set()
    for i in range(n):
        val = struct.unpack_from('<I', code, i * 4)[0]
        if not (val & OPCODE_MASK) and start <= val < end:
            result.add(val)
    return result


# ============================================================
#  EXTRACT
# ============================================================
def do_extract(code_path, data_path, out_path):
    with open(code_path, 'rb') as f:
        code = f.read()
    with open(data_path, 'rb') as f:
        data = decode_data(f.read())

    entries = collect_text_entries(code)
    print(f'[extract] Found {len(entries)} text entries')

    result = []
    for i, e in enumerate(entries):
        label_raw = read_str_at(data, e['label_idx'])
        text_raw  = read_str_at(data, e['text1_idx'])

        item = OrderedDict()
        item['id'] = i
        item['label'] = label_raw.decode(READ_ENCODING)

        if e['speaker_idx'] != 0:
            spk_raw = read_str_at(data, e['speaker_idx'])
            item['name'] = spk_raw.decode(READ_ENCODING).rstrip('\r')

        item['message'] = text_raw.decode(READ_ENCODING).replace('\r', '\n')
        result.append(item)

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f'[extract] Wrote {len(result)} entries to {out_path}')


# ============================================================
#  INJECT
# ============================================================
def do_inject(code_path, data_path, json_path, out_dir, write_enc):
    with open(code_path, 'rb') as f:
        code = bytearray(f.read())
    with open(data_path, 'rb') as f:
        data = bytearray(decode_data(f.read()))
    with open(json_path, 'r', encoding='utf-8') as f:
        translations = json.load(f)

    trans_map = {item['id']: item for item in translations}
    entries = collect_text_entries(bytes(code))
    print(f'[inject] {len(entries)} text entries, {len(trans_map)} translations')

    # --- Phase 1: Collect all indices ---
    data_end_idx = len(data) // 4
    text_indices = collect_indices(bytes(code), TEXT_START_IDX, TEXT_END_IDX)
    post_indices = collect_indices(bytes(code), TEXT_END_IDX, data_end_idx)
    sorted_all = sorted(text_indices | post_indices)
    print(f'[inject] Text indices: {len(text_indices)}, Post-text indices: {len(post_indices)}')

    # --- Phase 2: Read all original strings ---
    old_strings = {}
    for idx in sorted_all:
        old_strings[idx] = read_str_at(bytes(data), idx)

    # --- Phase 3: Apply translations ---
    new_strings = dict(old_strings)

    for i, e in enumerate(entries):
        if i not in trans_map:
            continue
        t = trans_map[i]

        new_text = t['message'].replace('\n', '\r')
        new_text_bytes = new_text.encode(write_enc)
        new_strings[e['text1_idx']] = new_text_bytes
        new_strings[e['text2_idx']] = new_text_bytes

        if 'name' in t and e['speaker_idx'] != 0:
            new_speaker = t['name'] + '\r'
            new_strings[e['speaker_idx']] = new_speaker.encode(write_enc)

    # --- Phase 4: Rebuild DATA.SSB ---
    pre_text_end = TEXT_START_IDX * 4
    new_data = bytearray(data[:pre_text_end])

    idx_map = {}
    current_idx = TEXT_START_IDX

    for old_idx in sorted_all:
        raw = new_strings[old_idx]
        padded_len = align4(len(raw) + 1)

        idx_map[old_idx] = current_idx
        new_data.extend(raw)
        new_data.extend(b'\x00' * (padded_len - len(raw)))
        current_idx += padded_len // 4

    delta = len(new_data) - len(data)
    print(f'[inject] Rebuilt {len(idx_map)} strings')
    print(f'[inject] DATA size: {len(data)} -> {len(new_data)} ({delta:+d} bytes)')

    # --- Phase 5: Patch CODE.SSB ---
    n = len(code) // 4
    patch_count = 0
    for i in range(n):
        val = struct.unpack_from('<I', code, i * 4)[0]
        if not (val & OPCODE_MASK) and val in idx_map:
            struct.pack_into('<I', code, i * 4, idx_map[val])
            patch_count += 1
    print(f'[inject] Patched {patch_count} CODE references')

    # --- Phase 6: Write output ---
    os.makedirs(out_dir, exist_ok=True)
    code_out = os.path.join(out_dir, 'CODE.SSB')
    data_out = os.path.join(out_dir, 'DATA.SSB')

    with open(code_out, 'wb') as f:
        f.write(bytes(code))
    with open(data_out, 'wb') as f:
        f.write(encode_data(bytes(new_data)))

    print(f'[inject] Output: {code_out} ({len(code)}B), {data_out} ({len(new_data)}B)')


# ============================================================
#  MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='月下の契り SSB Script Text Tool (SAISYS Engine)')
    sub = parser.add_subparsers(dest='command')

    p_ext = sub.add_parser('extract', help='Extract text to JSON')
    p_ext.add_argument('code', help='CODE.SSB path')
    p_ext.add_argument('data', help='DATA.SSB path')
    p_ext.add_argument('-o', '--output', default='ssb_text.json',
                       help='Output JSON (default: ssb_text.json)')

    p_inj = sub.add_parser('inject', help='Inject translated text')
    p_inj.add_argument('code', help='CODE.SSB path')
    p_inj.add_argument('data', help='DATA.SSB path')
    p_inj.add_argument('json', help='Translated JSON path')
    p_inj.add_argument('-o', '--output', default='output',
                       help='Output directory (default: output)')
    p_inj.add_argument('-e', '--encoding', default='cp932',
                       help='Write encoding (default: cp932, use gbk for Chinese)')

    args = parser.parse_args()
    if args.command == 'extract':
        do_extract(args.code, args.data, args.output)
    elif args.command == 'inject':
        do_inject(args.code, args.data, args.json, args.output, args.encoding)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
