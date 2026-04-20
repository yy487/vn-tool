#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
forget_bin_extract.py  --  textdata.bin → GalTransl JSON

textdata.bin 内部结构 (forget.exe / ペンギンワークス):

    +0  '\x00' '\x00'                 (2-byte head pad)
    +2  text[0] '\x00' u16_id[0]
        text[1] '\x00' u16_id[1]
        ...
        text[N-1] '\x00' u16_id[N-1]

  - text       : CP932 字符串, 大量使用半角片假名 (0xA1-0xDF), 90 年代风
  - u16_id     : LE, 单调递增 1..N (game-internal text id, 用于回想/存档)
  - 字符串起始字节偏移即是脚本里 MES/TLK/MENU opcode 引用的"text offset"

JSON 字段:
  id      = textdata 内的字节偏移 (与脚本字节码引用一致, 注入时也用它)
  uid     = textdata 内的 u16 id  (注入时原样保留, 不动)
  message = 译前/译后日文/中文
"""

import os, sys, struct, json, argparse


def parse_textdata(td: bytes):
    """返回 (records, head_pad, tail_pad).
    records = [(byte_offset, text_bytes, u16_id), ...]
    """
    head = b''
    if td[:2] == b'\x00\x00':
        head = td[:2]
        i = 2
    else:
        i = 0
    recs = []
    last_end = i
    while i < len(td):
        j = td.find(b'\x00', i)
        if j == -1:
            break
        if j + 3 > len(td):
            break
        text = td[i:j]
        idn = struct.unpack_from('<H', td, j + 1)[0]
        recs.append((i, text, idn))
        i = j + 3
        last_end = i
    return recs, head, td[last_end:]


def cmd_extract(args):
    td = open(args.textdata, 'rb').read()
    recs, head, tail = parse_textdata(td)
    out = []
    for off, raw, uid in recs:
        try:
            msg = raw.decode('cp932')
        except UnicodeDecodeError:
            msg = raw.decode('cp932', errors='replace')
        out.append({
            'id':      off,
            'uid':     uid,
            'name':    '',
            'message': msg,
        })
    with open(args.json, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f'[ok] extracted {len(out)} entries → {args.json}')
    print(f'     id range: {recs[0][0]:#x} .. {recs[-1][0]:#x}')
    print(f'     uid range: {recs[0][2]} .. {recs[-1][2]}')
    print(f'     head_pad={len(head)}B, tail_pad={len(tail)}B')


def main():
    ap = argparse.ArgumentParser(description='forget.exe textdata.bin extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('extract', help='textdata.bin → JSON')
    p.add_argument('textdata')
    p.add_argument('-o', '--json', default='textdata.json')
    p.set_defaults(func=cmd_extract)
    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
