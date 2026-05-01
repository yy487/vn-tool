#!/usr/bin/env python3
"""Generic AILSystem JSON text extractor.

Output keeps the old project JSON shape:
  id / pc / sub / kind / text_off / [name fields] / message / src_msg
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter

from ail_script_core import ScriptParser, pair_name_msg


def extract(path: str, *, version: int = 2, encoding: str = 'cp932', profile: str = 'generic',
            scan: str = 'both', resync: bool = False) -> dict:
    data = open(path, 'rb').read()
    parser = ScriptParser(data, version=version, encoding=encoding, profile=profile)
    events, stats = parser.scan_events(mode=scan, resync=resync)
    entries = pair_name_msg(events)
    return {
        'header': parser.hdr,
        'labels': parser.labels,
        'entries': entries,
        'stats': stats,
        'options': {'version': version, 'encoding': encoding, 'profile': profile, 'scan': scan, 'resync': resync},
    }


def write_outputs(result: dict, in_path: str, out_dir: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.basename(os.path.splitext(in_path)[0])
    entries = result['entries']

    # name table for translator-maintained speaker mapping
    name_counter = Counter(e.get('name') for e in entries if e.get('name'))
    name_table = {n: {'count': c, 'translation': n} for n, c in name_counter.most_common()}
    name_path = os.path.join(out_dir, stem + '_names.json')
    with open(name_path, 'w', encoding='utf-8') as f:
        json.dump(name_table, f, ensure_ascii=False, indent=2)

    json_out = []
    for e in entries:
        item = {
            'id': e['id'],
            'pc': e['pc'],
            'sub': e['sub'],
            'kind': e['kind'],
            'text_off': e['text_off'],
        }
        if e.get('name'):
            item['name'] = e['name']
            item['name_pc'] = e['name_pc']
            item['name_text_off'] = e['name_text_off']
        item['message'] = e['message']
        item['src_msg'] = e.get('src_msg', e['message'])
        json_out.append(item)

    out_path = os.path.join(out_dir, stem + '.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(json_out, f, ensure_ascii=False, indent=2)
    return out_path, name_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Generic AILSystem script extractor -> old project JSON format')
    ap.add_argument('input', help='decompressed AIL script .bin')
    ap.add_argument('out_dir', nargs='?', default='.', help='output directory')
    ap.add_argument('--version', type=int, default=2, choices=[0, 1, 2], help='AIL function table version; default: 2')
    ap.add_argument('--encoding', default='cp932', help='string encoding; default: cp932')
    ap.add_argument('--profile', default='generic', choices=['generic', 'bondage'], help='semantic profile; default: generic')
    ap.add_argument('--scan', default='both', choices=['labels', 'linear', 'both'], help='scan strategy; default: both')
    ap.add_argument('--resync', action='store_true', help='try byte-by-byte resync after parse errors; may create false positives')
    args = ap.parse_args(argv)

    result = extract(args.input, version=args.version, encoding=args.encoding, profile=args.profile,
                     scan=args.scan, resync=args.resync)
    out_path, name_path = write_outputs(result, args.input, args.out_dir)

    hdr = result['header']
    entries = result['entries']
    counter = Counter(e['kind'] for e in entries)
    stats = result['stats']
    print(f"bc_base={hdr['bc_base']:#x} text_base={hdr['text_base']:#x} labels={len(result['labels'])} bc_size={hdr['bc_size']:#x}")
    print(f"version={args.version} encoding={args.encoding} profile={args.profile} scan={args.scan} resync={args.resync}")
    print(f"提取 {len(entries)} 条 by kind: {dict(counter)}")
    print(f"扫描统计: blocks={stats.get('blocks', 0)} failed_blocks={stats.get('failed_blocks', 0)} linear_failed={stats.get('linear_failed', 0)}")
    print(f"含 name 配对: {sum(1 for e in entries if e.get('name'))}")
    print(f"-> {name_path}  (name 表)")
    print(f"-> {out_path}  ({len(entries)} 条)")

    if entries:
        print('\n样本前 15 条:')
        for e in entries[:15]:
            name = f"[{e['name']}] " if e.get('name') else ''
            print(f"  #{e['id']:4d} {e['kind']:<9} sub={e['sub']:02X} {name}{e['message'][:60]}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
