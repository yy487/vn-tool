#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查 replace_map 中 source_char 与 direct_cp932_chars 的码位冲突。"""
import json, sys
if len(sys.argv) < 2:
    print('Usage: python check_map_conflicts.py <replace_map.json>')
    sys.exit(1)
data = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
direct = set(data.get('direct_cp932_chars', []))
collisions = []
for target, ent in data.get('chars', {}).items():
    src = ent.get('source_char')
    if src in direct:
        collisions.append((target, src, ent.get('mode')))
print(f'direct_cp932_chars={len(direct)} mapped={len(data.get("chars", {}))} collisions={len(collisions)}')
for t, s, m in collisions[:200]:
    print(f'  {t} -> {s}  mode={m}')
if len(collisions) > 200:
    print(f'  ... {len(collisions)-200} more')
sys.exit(1 if collisions else 0)
