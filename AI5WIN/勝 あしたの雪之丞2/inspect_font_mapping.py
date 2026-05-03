#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inspect code/index relationship for AI5WIN FONT banks.

Usage:
  python inspect_font_mapping.py <replace_map.json> <font_dir> <text>
  python inspect_font_mapping.py build/replace_map.json build/DATA_FONT "啊无，叮咚权"
"""
import json, sys, os
from font_codec import load_bank, cp932_code, code_to_cp932_char
from text_normalize import normalize_text

if len(sys.argv) < 4:
    print(__doc__); sys.exit(1)
map_path, font_dir, text = sys.argv[1], sys.argv[2], sys.argv[3]
mp = json.load(open(map_path, 'r', encoding='utf-8'))
chars = mp.get('chars', {})
text_n = normalize_text(text)
print('text      :', text)
print('normalized:', text_n)
for bank_name in ('FONT00','FONT01','FONT02'):
    try:
        bank = load_bank(font_dir, bank_name)
    except Exception as e:
        print(f'[{bank_name}] load failed: {e}')
        continue
    idx_by_code = bank.code_to_index()
    print(f'\n[{bank_name}] count={len(bank.codes)} slots={bank.slot_count} spare={bank.slot_count-len(bank.codes)}')
    for ch in text_n:
        if ch in chars:
            src = chars[ch]['source_char']
            kind = 'mapped'
        else:
            src = ch
            kind = 'direct'
        try:
            code = cp932_code(src)
        except Exception as e:
            print(f'  {ch} -> {src} ({kind}) : NOT_CP932 {e}')
            continue
        idx = idx_by_code.get(code)
        tbl_ch = code_to_cp932_char(code)
        print(f'  {ch} -> {src} ({kind}) code=0x{code:04X} tbl_ch={tbl_ch!r} index={idx}')
