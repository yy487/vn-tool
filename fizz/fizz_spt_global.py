#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fizz SPT Global.dat reader (角色名字典)

用法 (CLI):
  fizz_spt_global.py info   global.dat              # 显示结构
  fizz_spt_global.py names  global.dat [out.json]   # 输出 nameSeq→name 映射

库用法:
  from fizz_spt_global import load_name_dict
  names = load_name_dict('global.dat')   # {0: 'みかげ', 17: '正宗', ...}

---- Global.dat 结构 (对齐 Core/SPT_Global.h) ----
  +0   EncryptorInfo (4B)                 同 SPT cryptor
  +4   UnFlag (u32)                       = 0
  +8   AppendScript[0..14]                15 个指令/事件表 (171+114+...)
         每个 = count(u32) + count × Entry
         Entry = StrLen0 + Str0 + StrLen1 + Str1 + 3×u32 + 0x80B append
  +?   GlobalStrCount (u32)               角色名数量
  +?   GlobalStr × count                  每个 260B cstring (CP932)
  +?   UnData (0x60B)
"""
import sys, struct, json
from pathlib import Path
from fizz_spt_cryptor import spt_decrypt

# ============================================================================
# 解析
# ============================================================================

def _skip_append_script(data, p):
    """跳过一个 Append_Script (含 count + entries)."""
    cnt = struct.unpack_from('<I', data, p)[0]; p += 4
    for _ in range(cnt):
        l0 = struct.unpack_from('<I', data, p)[0]; p += 4 + l0
        l1 = struct.unpack_from('<I', data, p)[0]; p += 4 + l1
        p += 12 + 0x80
    return p, cnt

def parse_global(global_dat_path):
    """解析 global.dat, 返回 {'names': [...], 'append_counts': [...]}"""
    raw = open(global_dat_path, 'rb').read()
    data = spt_decrypt(raw)  # 自动用文件头推参数

    p = 4  # skip EncryptorInfo
    un_flag = struct.unpack_from('<I', data, p)[0]; p += 4
    if un_flag != 0:
        raise ValueError(f"UnFlag != 0 ({un_flag:#x}), 格式未知")

    append_counts = []
    for _ in range(0xF):
        p, cnt = _skip_append_script(data, p)
        append_counts.append(cnt)

    count = struct.unpack_from('<I', data, p)[0]; p += 4
    names = []
    for _ in range(count):
        raw_name = data[p:p+260]
        end = raw_name.index(0) if 0 in raw_name else 260
        try:
            name = raw_name[:end].decode('cp932')
        except UnicodeDecodeError:
            name = raw_name[:end].decode('cp932', errors='replace')
        names.append(name)
        p += 260

    return {'names': names, 'append_counts': append_counts}

def load_name_dict(global_dat_path):
    """{nameSeq → name}. 0xFFFFFFFF (旁白) 不在字典中, 由调用方处理."""
    info = parse_global(global_dat_path)
    return {i: n for i, n in enumerate(info['names'])}

# ============================================================================
# CLI
# ============================================================================

def cli_info(args):
    info = parse_global(args.input)
    print(f'file: {args.input}')
    print(f'AppendScript counts (15 个): {info["append_counts"]}')
    print(f'GlobalStr count: {len(info["names"])}')

def cli_names(args):
    names = load_name_dict(args.input)
    if args.output:
        # 写成 {"0": "みかげ", ...} (JSON 字符串 key 兼容)
        Path(args.output).write_text(
            json.dumps({str(k): v for k, v in names.items()},
                       ensure_ascii=False, indent=2),
            encoding='utf-8')
        print(f'[names] wrote {len(names)} → {args.output}', file=sys.stderr)
    else:
        for i, n in names.items():
            print(f'  [{i:3d}] {n}')

def main():
    import argparse
    ap = argparse.ArgumentParser(description='Fizz SPT Global.dat reader')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('info'); p.add_argument('input'); p.set_defaults(func=cli_info)
    p = sub.add_parser('names'); p.add_argument('input'); p.add_argument('output', nargs='?'); p.set_defaults(func=cli_names)

    args = ap.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
