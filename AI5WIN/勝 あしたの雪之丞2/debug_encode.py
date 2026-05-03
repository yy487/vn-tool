#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""调试单句经过 replace_map 后的实际注入字节。"""
import argparse
from hanzi_replacer import ReplaceMapper

ap = argparse.ArgumentParser()
ap.add_argument('replace_map')
ap.add_argument('text')
args = ap.parse_args()
mapper = ReplaceMapper.load(args.replace_map)
normalized = mapper.normalize(args.text)
replaced = mapper.replace(args.text)
encoded = mapper.encode_cp932(args.text, require_double=True)
print('original  :', args.text)
print('normalized:', normalized)
print('source    :', replaced)
print('bytes     :', encoded.hex(' ').upper())
print('\nper char:')
for t, s in zip(normalized, replaced):
    if t == '\n':
        print('\\n')
        continue
    b = s.encode('cp932')
    print(f'{t} -> {s} -> {b.hex().upper()}')
