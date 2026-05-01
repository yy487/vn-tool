#!/usr/bin/env python3
"""Generic AILSystem JSON text injector.

Supports three injection modes:
  fixed  - overwrite original slots, truncate overflow, keep offsets unchanged
  append - append changed strings and patch known refs; unrecognized refs still point to old pool
  varlen - rebuild whole string pool and patch all recognized refs
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import tempfile
from typing import Optional

from ail_script_core import (
    ScriptParser,
    encode_cstring,
    iter_cstring_offsets,
    read_pool_string,
    safe_truncate_encoded,
    apply_text_map,
)


def load_json(path: Optional[str]) -> Optional[dict]:
    if not path:
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def load_name_map(json_path: str, name_table_path: Optional[str]) -> dict:
    if name_table_path is None:
        guess = os.path.splitext(json_path)[0] + '_names.json'
        if os.path.exists(guess):
            name_table_path = guess
    name_map = {}
    if name_table_path and os.path.exists(name_table_path):
        nt = load_json(name_table_path) or {}
        for k, v in nt.items():
            name_map[k] = v.get('translation', k) if isinstance(v, dict) else v
        print(f'[name] 加载 {len(name_map)} 个说话人映射')
    return name_map


def build_translations(entries: list, name_map: dict) -> dict:
    translations = {}
    for e in entries:
        if 'text_off' in e:
            translations[int(e['text_off'])] = e.get('message', e.get('src_msg', ''))
        if e.get('name') and e.get('name_text_off') is not None:
            orig_name = e['name']
            translated = name_map.get(orig_name, orig_name)
            translations[int(e['name_text_off'])] = '【' + translated + '】'
    return translations


def collect_refs(data: bytes, *, version: int, encoding: str, profile: str, scan: str, resync: bool) -> tuple[dict, dict]:
    parser = ScriptParser(data, version=version, encoding=encoding, profile=profile)
    return parser.collect_refs(mode=scan, resync=resync)


def make_slot_sizes(data: bytes, hdr: dict, orig_offs: list[int]) -> dict:
    slot_size = {}
    for idx, off in enumerate(orig_offs):
        if idx + 1 < len(orig_offs):
            slot_size[off] = orig_offs[idx + 1] - off
        else:
            slot_size[off] = (len(data) - hdr['text_base']) - off
    return slot_size


def patch_refs(data: bytearray, hdr: dict, refs: dict, off_map: dict) -> int:
    patch_count = 0
    for old_off, locations in refs.items():
        if old_off not in off_map:
            continue
        new_off = off_map[old_off]
        if new_off > 0xFFFF:
            raise OverflowError(f'new text offset exceeds u16: old={old_off:#x}, new={new_off:#x}')
        for pc_u16, _, _ in locations:
            struct.pack_into('<H', data, hdr['bc_base'] + pc_u16, new_off)
            patch_count += 1
    return patch_count


def inject(bin_path: str, json_path: str, out_path: str, *, name_table_path: Optional[str] = None,
           mode: str = 'varlen', version: int = 2, encoding: str = 'cp932', errors: str = 'replace',
           profile: str = 'generic', scan: str = 'both', resync: bool = False, map_path: Optional[str] = None,
           fix_path: Optional[str] = None) -> list:
    if mode not in ('varlen', 'fixed', 'append'):
        raise ValueError("mode must be one of: varlen, fixed, append")
    data = bytearray(open(bin_path, 'rb').read())
    parser = ScriptParser(bytes(data), version=version, encoding=encoding, profile=profile)
    hdr = parser.hdr
    entries = load_json(json_path) or []
    name_map = load_name_map(json_path, name_table_path)
    char_map = load_json(map_path)
    translations = build_translations(entries, name_map)

    refs, stats = collect_refs(bytes(data), version=version, encoding=encoding, profile=profile, scan=scan, resync=resync)
    print(f"[1/4] 扫描到 {len(refs)} 个唯一 text_off, 共 {sum(len(v) for v in refs.values())} 处引用")
    print(f"      blocks={stats.get('blocks', 0)} failed_blocks={stats.get('failed_blocks', 0)} linear_failed={stats.get('linear_failed', 0)}")

    orig_offs = iter_cstring_offsets(bytes(data), hdr)
    print(f"[2/4] 文本池原始 cstring: {len(orig_offs)} 条")
    slot_size = make_slot_sizes(bytes(data), hdr, orig_offs)

    name_for_off = {int(e['text_off']): e.get('name', '') for e in entries if e.get('name') and 'text_off' in e}
    fix_records = []

    if mode == 'fixed':
        new_pool = bytearray(data[hdr['text_base']:])
        changed = 0
        for old_off in orig_offs:
            if old_off not in translations:
                continue
            orig_start = old_off
            try:
                orig_end = new_pool.index(0, orig_start)
            except ValueError:
                orig_end = len(new_pool)
            orig_bytes = bytes(new_pool[orig_start:orig_end])
            orig_str = orig_bytes.decode(encoding, errors='replace')
            new_str = translations[old_off]
            if new_str == orig_str:
                continue
            raw_encoded = apply_text_map(new_str, char_map).encode(encoding, errors=errors)
            avail = max(0, slot_size[old_off] - 1)
            overflow = len(raw_encoded) - avail
            if overflow > 0:
                fixed = safe_truncate_encoded(raw_encoded, avail, encoding=encoding)
                fix_records.append({
                    'text_off': old_off,
                    'name': name_for_off.get(old_off, ''),
                    'orig_bytes': len(orig_bytes),
                    'slot_size': slot_size[old_off],
                    'trans_bytes': len(raw_encoded),
                    'overflow': overflow,
                    'orig_text': orig_str,
                    'trans_text': new_str,
                    'truncated_text': fixed.decode(encoding, errors='replace'),
                })
                payload = fixed
            else:
                payload = raw_encoded
            new_pool[orig_start:orig_start + slot_size[old_off]] = payload + b'\x00' * (slot_size[old_off] - len(payload))
            changed += 1
        new_file = bytearray(data[:hdr['text_base']])
        new_file.extend(new_pool)
        print(f"[3/4] fixed 覆盖 {changed} 条，截断 {len(fix_records)} 条")

    elif mode == 'append':
        new_file = bytearray(data)
        old_pool_size = len(data) - hdr['text_base']
        off_map = {}
        changed = 0
        for old_off in sorted(translations):
            if old_off not in refs:
                continue
            orig_str = read_pool_string(bytes(data), hdr, old_off, encoding)
            new_str = translations[old_off]
            if new_str == orig_str:
                continue
            new_off = len(new_file) - hdr['text_base']
            encoded = encode_cstring(new_str, encoding=encoding, errors=errors, mapping=char_map)
            if new_off > 0xFFFF:
                raise OverflowError(f'append text offset exceeds u16: {new_off:#x}')
            off_map[old_off] = new_off
            new_file.extend(encoded)
            changed += 1
        patch_count = patch_refs(new_file, hdr, refs, off_map)
        print(f"[3/4] append: 原文本池 {old_pool_size} B，追加 {len(new_file)-len(data)} B，变化 {changed} 条")
        print(f"      修补 {patch_count} 处 u16；未识别引用仍指向原文本")

    else:
        new_pool = bytearray()
        off_map = {}
        for old_off in orig_offs:
            orig_str = read_pool_string(bytes(data), hdr, old_off, encoding)
            new_str = translations.get(old_off, orig_str)
            off_map[old_off] = len(new_pool)
            if off_map[old_off] > 0xFFFF:
                raise OverflowError(f'new text offset exceeds u16: old={old_off:#x}, new={off_map[old_off]:#x}')
            if new_str == orig_str:
                # Preserve original bytes and padding exactly so untranslated round-trip can be bit-perfect.
                start = hdr['text_base'] + old_off
                new_pool.extend(data[start:start + slot_size[old_off]])
            else:
                encoded = encode_cstring(new_str, encoding=encoding, errors=errors, mapping=char_map)
                new_pool.extend(encoded)
        patch_count = patch_refs(data, hdr, refs, off_map)
        new_file = bytearray(data[:hdr['text_base']])
        new_file.extend(new_pool)
        print(f"[3/4] varlen: 文本池 {len(data)-hdr['text_base']} B -> {len(new_pool)} B")
        print(f"      修补 {patch_count} 处 u16")

    with open(out_path, 'wb') as f:
        f.write(new_file)
    print(f"[4/4] 写出 -> {out_path}")
    print(f"      原文件: {len(data)} B -> 新文件: {len(new_file)} B")

    if fix_records:
        if fix_path is None:
            stem = os.path.splitext(os.path.basename(out_path))[0]
            fix_path = os.path.join(os.path.dirname(out_path) or '.', stem + '_fix.json')
        with open(fix_path, 'w', encoding='utf-8') as f:
            json.dump(fix_records, f, ensure_ascii=False, indent=2)
        print(f"      截断记录 -> {fix_path}")
    return fix_records


def roundtrip_test(bin_path: str, *, version: int = 2, encoding: str = 'cp932', profile: str = 'generic', scan: str = 'both') -> bool:
    import ail_extract
    print('=' * 50)
    print('Round-trip 测试')
    print('=' * 50)
    result = ail_extract.extract(bin_path, version=version, encoding=encoding, profile=profile, scan=scan)
    tmp_dir = tempfile.mkdtemp(prefix='ail_rt_')
    tmp_json = os.path.join(tmp_dir, 'rt.json')
    tmp_bin = os.path.join(tmp_dir, 'rt.bin')
    with open(tmp_json, 'w', encoding='utf-8') as f:
        json.dump(result['entries'], f, ensure_ascii=False, indent=2)
    inject(bin_path, tmp_json, tmp_bin, mode='varlen', version=version, encoding=encoding, profile=profile, scan=scan)
    a = open(bin_path, 'rb').read()
    b = open(tmp_bin, 'rb').read()
    if a == b:
        print(f'OK ROUND-TRIP PASS: bit-perfect ({len(a)} B)')
        return True
    diffs = sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))
    print(f'FAIL ROUND-TRIP: {diffs} bytes diff, {len(a)} vs {len(b)}')
    for k, (x, y) in enumerate(zip(a, b)):
        if x != y:
            print(f'  @ {k:#x}: {x:#04x} != {y:#04x}')
            if k > 10:
                break
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Generic AILSystem JSON injector')
    sub = ap.add_subparsers(dest='cmd', required=True)

    rt = sub.add_parser('roundtrip', help='extract and inject without changes')
    rt.add_argument('bin_path')

    inj = sub.add_parser('inject', help='inject JSON into script')
    inj.add_argument('bin_path')
    inj.add_argument('json_path')
    inj.add_argument('out_bin')

    for p in (rt, inj):
        p.add_argument('--version', type=int, default=2, choices=[0, 1, 2])
        p.add_argument('--encoding', default='cp932')
        p.add_argument('--profile', default='generic', choices=['generic', 'bondage'])
        p.add_argument('--scan', default='both', choices=['labels', 'linear', 'both'])
        p.add_argument('--resync', action='store_true')

    inj.add_argument('--mode', default='varlen', choices=['varlen', 'fixed', 'append'])
    inj.add_argument('--fixed', action='store_true', help='compat alias for --mode fixed')
    inj.add_argument('--append', action='store_true', help='compat alias for --mode append')
    inj.add_argument('--names', dest='name_table_path')
    inj.add_argument('--errors', default='replace', choices=['strict', 'replace', 'ignore'])
    inj.add_argument('--map', dest='map_path', help='optional JSON char/phrase mapping before encoding')
    inj.add_argument('--fix', dest='fix_path', help='where to write fixed-mode truncation report')

    args = ap.parse_args(argv)
    if args.cmd == 'roundtrip':
        ok = roundtrip_test(args.bin_path, version=args.version, encoding=args.encoding, profile=args.profile, scan=args.scan)
        return 0 if ok else 1
    mode = args.mode
    if args.fixed:
        mode = 'fixed'
    if args.append:
        mode = 'append'
    inject(args.bin_path, args.json_path, args.out_bin, name_table_path=args.name_table_path, mode=mode,
           version=args.version, encoding=args.encoding, errors=args.errors, profile=args.profile,
           scan=args.scan, resync=args.resync, map_path=args.map_path, fix_path=args.fix_path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
