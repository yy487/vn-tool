#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HIMITSU ISF 脚本文本提取工具

输入: 一个目录, 含已解密 (或加密) 的 .isf 文件
输出: 一个 JSON, 按文件名分组, 每条含 idx/kind/op/name/ori/message/_raw/_tail 等元信息

用法:
    # 目录内是加密 .ISF (从 isf_arc unpack 直出):
    python isf_extract.py mes/ dump.json --encrypted

    # 目录内是已解密 .isf (用 isf_crypt dec-dir 处理过):
    python isf_extract.py mes/ dump.json

元信息字段 (不能被翻译器改):
    _raw        原始文本字节 (hex), 当 message == ori 时回填不依赖清洗逻辑
    _tail       title/ui 指令尾部字节 (hex)
    _tail_zeros sys 指令尾部 0x00 的数量
    has_name_br talk 原文带 "】 00 06 FF 「" 名字框, 注入时要还原
"""
import os, sys, json, re, argparse
from isf_script import (
    isf_decrypt, parse_script, sjis_decode, SUB_FIXED_LEN,
    decode_himitsu_text, encode_himitsu_text,
)

NAME_BR_RE = re.compile(r'^【(.*?)】(.*)', re.S)

def _find_talk_payload_start(content: bytes):
    if not content: return None
    off = 1
    while off < len(content):
        cmd = content[off]; off += 1
        if cmd in SUB_FIXED_LEN:
            off += SUB_FIXED_LEN[cmd]
        elif cmd == 0xFF:
            return off
    return None

def dump_ops(ops, split_embedded=True):
    items = []
    for i, op in enumerate(ops):
        o = op['op']; c = op['content']
        if o in (0x2b, 0x2c):
            pstart = _find_talk_payload_start(c)
            if pstart is None: continue
            # 从 content 里扫 0x11 cmd 取 name_id (如果存在)
            name_id = None
            _off = 1
            while _off < pstart - 1:
                _cmd = c[_off]; _off += 1
                if _cmd == 0x11 and _off + 4 <= len(c):
                    name_id = int.from_bytes(c[_off:_off+4], 'little')
                    _off += 4
                elif _cmd in SUB_FIXED_LEN:
                    _off += SUB_FIXED_LEN[_cmd]
                elif _cmd == 0xFF:
                    break
            payload = c[pstart:]
            stripped = payload.rstrip(b'\x00')
            tail_zeros = len(payload) - len(stripped)
            if not stripped:
                continue
            txt = decode_himitsu_text(stripped)
            name = ''
            msg = txt
            if split_embedded:
                m = NAME_BR_RE.match(txt)
                if m:
                    name = m.group(1); msg = m.group(2)
            e = {'idx': i, 'kind': 'talk', 'op': o, 'name': name,
                 'ori': txt, 'message': msg,
                 '_raw': stripped.hex(),
                 '_tail_zeros': tail_zeros}
            if name_id is not None:
                e['name_id'] = name_id
            items.append(e)
        elif o == 0xF7 and len(c) > 1:
            items.append({'idx': i, 'kind': 'title', 'op': o,
                          'ori': sjis_decode(c[:-1]), 'message': sjis_decode(c[:-1]),
                          '_tail': c[-1:].hex()})
        elif o == 0xE0 and len(c) > 2:
            items.append({'idx': i, 'kind': 'ui', 'op': o, 'prefix': 1,
                          'ori': sjis_decode(c[1:-1]), 'message': sjis_decode(c[1:-1]),
                          '_tail': c[-1:].hex()})
        elif o == 0xE1 and len(c) > 3:
            items.append({'idx': i, 'kind': 'ui', 'op': o, 'prefix': 2,
                          'ori': sjis_decode(c[2:-1]), 'message': sjis_decode(c[2:-1]),
                          '_tail': c[-1:].hex()})
        elif o in (0xE2, 0xE3) and len(c) > 6:
            items.append({'idx': i, 'kind': 'ui', 'op': o, 'prefix': 5,
                          'ori': sjis_decode(c[5:-1]), 'message': sjis_decode(c[5:-1]),
                          '_tail': c[-1:].hex()})
        elif o == 0x15 and len(c) > 0x12:
            nb = c[0x12:]
            stripped = nb.rstrip(b'\x00')
            if stripped:
                items.append({'idx': i, 'kind': 'sys', 'op': o, 'prefix': 0x12,
                              'ori': sjis_decode(stripped), 'message': sjis_decode(stripped),
                              '_tail_zeros': len(nb) - len(stripped)})
        elif o == 0x25 and len(c) > 2:
            nb = c[2:]
            stripped = nb.rstrip(b'\x00')
            if stripped:
                items.append({'idx': i, 'kind': 'sys', 'op': o, 'prefix': 2,
                              'ori': sjis_decode(stripped), 'message': sjis_decode(stripped),
                              '_tail_zeros': len(nb) - len(stripped)})
    return items

def main():
    ap = argparse.ArgumentParser(description='HIMITSU ISF 文本提取')
    ap.add_argument('dir', help='.isf 所在目录')
    ap.add_argument('out', help='输出 JSON 路径')
    ap.add_argument('--encrypted', action='store_true',
                    help='目录内 .isf 是加密的 (从 isf_arc unpack 直出), 先解密再解析')
    args = ap.parse_args()

    files = sorted(f for f in os.listdir(args.dir) if f.lower().endswith('.isf'))
    result = {}
    total = 0
    for name in files:
        p = os.path.join(args.dir, name)
        raw = open(p, 'rb').read()
        plain = isf_decrypt(raw) if args.encrypted else raw
        try:
            _, _, _, ops, _ = parse_script(plain)
        except Exception as e:
            print(f'  [!] {name}: 解析失败 {e}')
            continue
        items = dump_ops(ops)
        if items:
            result[name] = items
            total += len(items)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f'[extract] {len(result)} 个文件 / {total} 条文本 → {args.out}')

if __name__ == '__main__':
    main()
