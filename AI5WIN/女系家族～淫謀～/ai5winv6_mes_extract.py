#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI5WIN V6 MES 文本提取工具
===========================

从 AI5WIN V6 剧情 MES 文件提取 SJIS 文本, 输出 GalTransl 兼容 JSON.

用法:
  python3 ai5winv6_mes_extract.py batch  <mes_dir>  <out_dir>
  python3 ai5winv6_mes_extract.py single <mes_file> <out_json>

输出 JSON 格式 (GalTransl 兼容):
  [
    {
      "name": "祥子",
      "message": "「...」",
      "id": "01-01.MES#3#0"
    },
    ...
  ]

设计要点:
- 提取基于完整 bytecode 反汇编 (复用 inject 同一套逻辑),
  确保 extract/inject 的 text_idx 完全一致
- 每条 0x01 TEXT 指令作为一个独立条目
- UI MES (FE ED F1 1B 开头) 和非 .MES 自动跳过
- 角色名规则: `XXX「...」` -> name=XXX, message=「...」
  否则 name="", message=text (旁白)
"""

import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ai5v6_codec import load_mes, is_compressed_story_mes
from ai5v6_bytecode import disassemble

ENCODING = 'cp932'


def _has_japanese(s: str) -> bool:
    for c in s:
        if ('\u3040' <= c <= '\u309f' or
            '\u30a0' <= c <= '\u30ff' or
            '\u4e00' <= c <= '\u9fff'):
            return True
    return False


def split_name_message(text: str) -> tuple:
    """按 `角色名「对话」` 规则拆分 name / message."""
    pos = text.find('「')
    if pos <= 0:
        return "", text
    name_part = text[:pos]
    if any(c in name_part for c in '。、？！…「」『』（）\n\u3000'):
        return "", text
    if len(name_part) > 8:
        return "", text
    return name_part, text[pos:]


def extract_mes_file(mes_bytes: bytes, file_name: str) -> list:
    """提取单个 MES 文件, 返回 JSON 条目列表.
    
    返回 None 表示文件不是剧情 MES.
    """
    if not is_compressed_story_mes(mes_bytes):
        return None

    try:
        script = load_mes(mes_bytes)
    except Exception as e:
        print(f"  [!] {file_name}: parse failed - {e}", file=sys.stderr)
        return None

    instrs = disassemble(script.bytecode)

    entries = []
    msg_idx = -1
    text_idx = 0

    for inst in instrs:
        if inst.opcode == 0x17:
            msg_idx += 1
            text_idx = 0
            continue
        if inst.opcode != 0x01:
            continue
        if inst.text is None or not _has_japanese(inst.text):
            continue
        name, message = split_name_message(inst.text)
        entries.append({
            "name": name,
            "message": message,
            "id": f"{file_name}#{msg_idx}#{text_idx}",
        })
        text_idx += 1

    return entries


def cmd_batch(mes_dir: str, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    files = sorted(f for f in os.listdir(mes_dir)
                   if f.upper().endswith('.MES'))
    if not files:
        print(f"[!] No .MES files found in {mes_dir}")
        return

    total_entries = 0
    processed = 0
    skipped = 0

    for fn in files:
        path = os.path.join(mes_dir, fn)
        with open(path, 'rb') as f:
            data = f.read()

        entries = extract_mes_file(data, fn)
        if entries is None:
            skipped += 1
            continue

        out_path = os.path.join(out_dir, fn[:-4] + '.json')
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)

        processed += 1
        total_entries += len(entries)
        print(f"  [{processed:3d}] {fn} -> {len(entries)} texts")

    print(f"\n[+] Processed: {processed} files, {total_entries} text entries")
    print(f"[+] Skipped: {skipped} files (UI MES / invalid)")
    print(f"[+] Output: {out_dir}")


def cmd_single(mes_file: str, out_json: str):
    with open(mes_file, 'rb') as f:
        data = f.read()

    fn = os.path.basename(mes_file)
    entries = extract_mes_file(data, fn)
    if entries is None:
        print(f"[!] {fn} is a UI MES or invalid, no text extracted")
        return

    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    print(f"[+] Extracted {len(entries)} texts from {fn} -> {out_json}")


def main():
    ap = argparse.ArgumentParser(description='AI5WIN V6 MES text extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_batch = sub.add_parser('batch', help='Batch extract directory')
    p_batch.add_argument('mes_dir')
    p_batch.add_argument('out_dir')

    p_single = sub.add_parser('single', help='Extract single MES file')
    p_single.add_argument('mes_file')
    p_single.add_argument('out_json')

    args = ap.parse_args()
    if args.cmd == 'batch':
        cmd_batch(args.mes_dir, args.out_dir)
    elif args.cmd == 'single':
        cmd_single(args.mes_file, args.out_json)


if __name__ == '__main__':
    main()
