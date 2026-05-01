#!/usr/bin/env python3
"""Compatibility wrapper for BONDAGE-style injection.

The real generic implementation is ail_inject.py. Defaults stay CP932,
version=2, profile=bondage.
"""
from __future__ import annotations

import argparse
import sys

import ail_inject


def inject(bin_path: str, json_path: str, out_path: str, name_table_path: str = None,
           mode: str = 'varlen', fix_path: str = None) -> list:
    return ail_inject.inject(
        bin_path, json_path, out_path,
        name_table_path=name_table_path,
        mode=mode,
        version=2,
        encoding='cp932',
        errors='replace',
        profile='bondage',
        scan='both',
        fix_path=fix_path,
    )


def roundtrip_test(bin_path: str):
    return ail_inject.roundtrip_test(bin_path, version=2, encoding='cp932', profile='bondage', scan='both')


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='BONDAGE-compatible injector using the generic AIL parser')
    sub = ap.add_subparsers(dest='cmd', required=True)
    rt = sub.add_parser('roundtrip')
    rt.add_argument('bin_path')
    inj = sub.add_parser('inject')
    inj.add_argument('bin_path')
    inj.add_argument('json_path')
    inj.add_argument('out_bin')
    inj.add_argument('--mode', default='varlen', choices=['varlen', 'fixed', 'append'])
    inj.add_argument('--fixed', action='store_true')
    inj.add_argument('--append', action='store_true')
    inj.add_argument('--names')
    inj.add_argument('--errors', default='replace', choices=['strict', 'replace', 'ignore'])
    inj.add_argument('--map')
    args = ap.parse_args(argv)
    if args.cmd == 'roundtrip':
        return 0 if roundtrip_test(args.bin_path) else 1
    mode = args.mode
    if args.fixed:
        mode = 'fixed'
    if args.append:
        mode = 'append'
    ail_inject.inject(
        args.bin_path, args.json_path, args.out_bin,
        name_table_path=args.names,
        mode=mode,
        version=2,
        encoding='cp932',
        errors=args.errors,
        profile='bondage',
        scan='both',
        map_path=args.map,
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
