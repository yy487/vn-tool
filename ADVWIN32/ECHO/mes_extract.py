#!/usr/bin/env python3
"""
mes_extract.py - ADVWIN32 MES script text extractor
Engine: ADVWIN32 (F&C Co., Ltd.)

Usage:
    python mes_extract.py <unpacked_dir> -o texts.json

Only extracts from numeric-named MES files (e.g. 00014000.MES, 40066000.MES).
System/animation MES files (STARTUP.MES, ANM*.MES, etc.) are skipped.
"""

import json
import sys
import os
import re
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
    if 0xA1 <= b <= 0xDF:  # half-width kana
        return True
    if 0x30 <= b <= 0x39:  # digits
        return True
    if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:  # A-Z, a-z
        return True
    if b in (0x20, 0x11):  # another space or next text line
        return True
    return False


def read_text_at(data, pos):
    """
    Read CP932 text starting at pos.
    Terminates at:
      - 0x00 (null)
      - byte < 0x20 except 0x0A (control/opcode byte)
      - 0x20 (space) followed by a non-text byte (opcode like 0x13, 0x2F, etc.)
    """
    j = pos
    while j < len(data):
        b = data[j]
        if b == 0x00:
            break
        if b < 0x20 and b != 0x0A:
            break
        if b == 0x20:
            # Peek next byte: if it's not a text-continuation byte, terminate here
            if j + 1 < len(data) and not _can_continue_after_space(data[j + 1]):
                j += 1  # include the trailing space
                break
            j += 1
            continue
        if is_cp932_lead(b) and j + 1 < len(data):
            trail = data[j + 1]
            if (0x40 <= trail <= 0x7E) or (0x80 <= trail <= 0xFC):
                j += 2
            else:
                return None  # invalid CP932 sequence = not text
        elif 0x21 <= b <= 0x7E or (0xA1 <= b <= 0xDF) or b == 0x0A:
            j += 1
        else:
            return None
    if j > pos:
        try:
            text = data[pos:j].decode('cp932')
            next_pos = j + 1 if j < len(data) and data[j] == 0x00 else j
            return (text, next_pos)
        except UnicodeDecodeError:
            return None
    return None


def find_speaker_before(data, text_pos):
    """Find nearest E5 speaker name before a CB 01 2F text block."""
    search_start = max(MES_HEADER_SIZE, text_pos - 200)
    for i in range(text_pos - 3, search_start, -1):
        if data[i:i + 3] == b'\xCB\x01\x2F':
            for j in range(i - 1, max(search_start, i - 100), -1):
                if data[j] == STRING_OPCODE:
                    k = j + 1
                    while k < i and data[k] != 0x00:
                        k += 1
                    if k < i:
                        try:
                            name = data[j + 1:k].decode('cp932')
                            if '.' in name or 'regprint' in name:
                                continue
                            return name
                        except UnicodeDecodeError:
                            pass
                    break
            break
    return ''


def extract_file(data):
    """Extract all text entries from one MES file."""
    entries = []
    pos = MES_HEADER_SIZE
    text_id = 0

    while pos < len(data):
        if data[pos] != TEXT_OPCODE:
            pos += 1
            continue

        result = read_text_at(data, pos + 1)
        if result is None:
            pos += 1
            continue

        text, next_pos = result
        block_start = pos

        # Collect consecutive 0x11 lines (multi-line dialogue)
        lines = [text]
        scan = next_pos
        while scan < len(data) and data[scan] == TEXT_OPCODE:
            r = read_text_at(data, scan + 1)
            if r is None:
                break
            lines.append(r[0])
            scan = r[1]

        speaker = find_speaker_before(data, block_start)
        message = ''.join(lines).rstrip('\n ')

        text_id += 1

        # Skip empty/whitespace-only
        if not message.strip():
            pos = scan
            continue

        entries.append({
            'id': text_id - 1,
            'name': speaker,
            'message': message,
        })
        pos = scan

    return entries


def is_script_file(filename):
    """Check if file is a numeric-named script MES (e.g. 00014000.MES)."""
    name = os.path.splitext(filename)[0]
    return bool(re.match(r'^\d+$', name))


def main():
    parser = argparse.ArgumentParser(description='ADVWIN32 MES text extractor')
    parser.add_argument('input', help='Unpacked MES directory')
    parser.add_argument('-o', '--output', default='texts.json', help='Output JSON file')
    args = parser.parse_args()

    indir = args.input
    all_entries = []
    file_count = 0

    for fn in sorted(os.listdir(indir)):
        if not fn.upper().endswith('.MES'):
            continue
        if not is_script_file(fn):
            continue

        filepath = os.path.join(indir, fn)
        with open(filepath, 'rb') as f:
            data = f.read()

        if len(data) < MES_HEADER_SIZE:
            continue

        entries = extract_file(data)
        if entries:
            for e in entries:
                e['file'] = fn
            all_entries.extend(entries)
            file_count += 1

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(all_entries, f, ensure_ascii=False, indent=2)

    print(f'Extracted {len(all_entries)} entries from {file_count} script files')
    print(f'Output: {args.output} ({os.path.getsize(args.output):,} bytes)')


if __name__ == '__main__':
    main()
