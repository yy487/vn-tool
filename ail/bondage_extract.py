#!/usr/bin/env python3
"""Compatibility wrapper for BONDAGE-style extraction.

The real generic implementation is ail_extract.py. This wrapper keeps the old
entry-point name and defaults to --profile bondage so existing batch scripts keep
working while using the new AIL opcode/expr parser.
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter

import ail_extract


def extract(path: str) -> dict:
    result = ail_extract.extract(path, version=2, encoding='cp932', profile='bondage', scan='both')
    # old batch code expected e['type']; keep an alias for compatibility
    for e in result['entries']:
        e['type'] = e.get('kind', e.get('type', 'msg_other'))
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='BONDAGE-compatible extractor using the generic AIL parser')
    ap.add_argument('input')
    ap.add_argument('out_dir', nargs='?', default='.')
    ap.add_argument('--scan', default='both', choices=['labels', 'linear', 'both'])
    ap.add_argument('--resync', action='store_true')
    args = ap.parse_args(argv)
    if not os.path.isfile(args.input):
        print(f'[ERR] 文件不存在: {args.input}')
        return 1
    result = ail_extract.extract(args.input, version=2, encoding='cp932', profile='bondage', scan=args.scan, resync=args.resync)
    for e in result['entries']:
        e['type'] = e.get('kind', e.get('type', 'msg_other'))
    out_path, name_path = ail_extract.write_outputs(result, args.input, args.out_dir)
    hdr = result['header']
    entries = result['entries']
    c = Counter(e.get('kind', e.get('type')) for e in entries)
    print(f"bc_base={hdr['bc_base']:#x} text_base={hdr['text_base']:#x} labels={len(result['labels'])} bc_size={hdr['bc_size']:#x}")
    print(f"提取 {len(entries)} 条 by kind: {dict(c)}")
    print(f"含 name 配对: {sum(1 for e in entries if e.get('name'))}")
    print(f"-> {name_path}  (name 表)")
    print(f"-> {out_path}  ({len(entries)} 条)")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
