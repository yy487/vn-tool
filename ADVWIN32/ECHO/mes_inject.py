#!/usr/bin/env python3
"""
mes_inject.py - ADVWIN32 MES script text injector
Engine: ADVWIN32 (F&C Co., Ltd.)

Usage:
    python mes_inject.py <orig_unpacked_dir> <texts.json> -o <patched_dir>

Injects translated text into MES files. Non-script MES files (system, animation, etc.)
are copied verbatim from the original directory.
"""

import json
import sys
import os
import re
import shutil
import argparse

MES_HEADER_SIZE = 0x20
TEXT_OPCODE = 0x11
STRING_OPCODE = 0xE5


def is_cp932_lead(b):
    return (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xEF)


def _can_continue_after_space(b):
    """After 0x20 (space), check if the next byte is still text content."""
    if is_cp932_lead(b):
        return True
    if 0xA1 <= b <= 0xDF:
        return True
    if 0x30 <= b <= 0x39:
        return True
    if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:
        return True
    if b in (0x20, 0x11):
        return True
    return False


def read_text_at(data, pos):
    """Read text at pos, returns (raw_bytes, text_str, next_pos, term_type) or None."""
    j = pos
    while j < len(data):
        b = data[j]
        if b == 0x00:
            if j == pos:
                return None  # empty text
            raw = data[pos:j]
            return (raw, raw.decode('cp932', errors='replace'), j + 1, 'null')
        if b < 0x20 and b != 0x0A:
            if j == pos:
                return None  # no text before control byte
            raw = data[pos:j]
            return (raw, raw.decode('cp932', errors='replace'), j, 'opcode')
        if b == 0x20:
            if j + 1 < len(data) and not _can_continue_after_space(data[j + 1]):
                raw = data[pos:j + 1]  # include trailing space
                return (raw, raw.decode('cp932', errors='replace'), j + 1, 'space')
            j += 1
            continue
        if is_cp932_lead(b) and j + 1 < len(data):
            trail = data[j + 1]
            if (0x40 <= trail <= 0x7E) or (0x80 <= trail <= 0xFC):
                j += 2
            else:
                if j == pos:
                    return None
                raw = data[pos:j]
                return (raw, raw.decode('cp932', errors='replace'), j, 'opcode')
        elif 0x21 <= b <= 0x7E or (0xA1 <= b <= 0xDF) or b == 0x0A:
            j += 1
        else:
            return None
    return None


def is_script_file(filename):
    name = os.path.splitext(filename)[0]
    return bool(re.match(r'^\d+$', name))


def inject_file(data, translations):
    """
    Inject translations into a MES file.
    translations: dict mapping text_id -> new_message string
    Returns new file data.
    """
    result = bytearray()
    result.extend(data[:MES_HEADER_SIZE])

    pos = MES_HEADER_SIZE
    text_id = 0

    while pos < len(data):
        if data[pos] != TEXT_OPCODE:
            result.append(data[pos])
            pos += 1
            continue

        r = read_text_at(data, pos + 1)
        if r is None:
            result.append(data[pos])
            pos += 1
            continue

        # Collect all consecutive 0x11 lines for this block
        block_lines = []  # [(raw_bytes, text, next_pos, term_type)]
        scan = pos
        while scan < len(data) and data[scan] == TEXT_OPCODE:
            lr = read_text_at(data, scan + 1)
            if lr is None:
                break
            block_lines.append((scan, lr))
            scan = lr[2]

        orig_message = ''.join(lr[1] for _, lr in block_lines).rstrip('\n ')
        current_id = text_id
        text_id += 1

        # Skip empty blocks (same logic as extract)
        if not orig_message.strip():
            # Write original bytes verbatim
            for line_pos, lr in block_lines:
                raw, text, next_pos, term = lr
                result.append(TEXT_OPCODE)
                result.extend(raw)
                if term == 'null':
                    result.append(0x00)
            pos = scan
            continue

        if current_id in translations and translations[current_id] != orig_message:
            new_msg = translations[current_id]
            try:
                new_bytes = new_msg.encode('cp932')
            except UnicodeEncodeError:
                new_bytes = new_msg.encode('gbk', errors='replace')

            # Emit as single 0x11 block with same termination as last original line
            last_term = block_lines[-1][1][3]
            result.append(TEXT_OPCODE)
            result.extend(new_bytes)
            if last_term == 'null':
                result.append(0x00)
        else:
            # No change - copy original bytes verbatim
            for line_pos, lr in block_lines:
                raw, text, next_pos, term = lr
                result.append(TEXT_OPCODE)
                result.extend(raw)
                if term == 'null':
                    result.append(0x00)

        pos = scan

    # Update file size in header [0x14] only if size changed
    if len(result) != len(data):
        import struct
        struct.pack_into('<I', result, 0x14, len(result))

    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description='ADVWIN32 MES text injector')
    parser.add_argument('orig_dir', help='Original unpacked MES directory')
    parser.add_argument('texts', help='Translated texts JSON file')
    parser.add_argument('-o', '--output', required=True, help='Output patched directory')
    args = parser.parse_args()

    orig_dir = args.orig_dir
    out_dir = args.output
    os.makedirs(out_dir, exist_ok=True)

    # Load translations grouped by file
    with open(args.texts, 'r', encoding='utf-8') as f:
        entries = json.load(f)

    trans_by_file = {}
    for e in entries:
        fn = e['file']
        if fn not in trans_by_file:
            trans_by_file[fn] = {}
        trans_by_file[fn][e['id']] = e['message']

    injected_count = 0
    copied_count = 0

    for fn in sorted(os.listdir(orig_dir)):
        if not fn.upper().endswith('.MES') and not fn.upper().endswith('.MEC'):
            continue

        src_path = os.path.join(orig_dir, fn)
        dst_path = os.path.join(out_dir, fn)

        if is_script_file(fn) and fn in trans_by_file:
            # Inject translations
            with open(src_path, 'rb') as f:
                data = f.read()

            new_data = inject_file(data, trans_by_file[fn])
            with open(dst_path, 'wb') as f:
                f.write(new_data)
            injected_count += 1
        else:
            # Copy verbatim
            shutil.copy2(src_path, dst_path)
            copied_count += 1

    print(f'Injected: {injected_count} files')
    print(f'Copied (unchanged): {copied_count} files')
    print(f'Output: {out_dir}/')


if __name__ == '__main__':
    main()
