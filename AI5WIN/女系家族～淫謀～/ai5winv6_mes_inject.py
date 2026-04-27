#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI5WIN V6 MES 文本注入工具
===========================

把翻译后的 GalTransl JSON 注入回 AI5WIN V6 剧情 MES 文件.

用法:
  python3 ai5winv6_mes_inject.py batch  <mes_in_dir> <json_dir> <mes_out_dir>
  python3 ai5winv6_mes_inject.py single <mes_in>      <json>     <mes_out>
  python3 ai5winv6_mes_inject.py verify <mes_in>
    (反汇编 -> 原样重组装, 验证工具链对该文件是否无损)

特性:
- 完整变长注入: 支持译文字节数任意变化
- 基于 v2 opcode 表做完整 bytecode 反汇编
- 自动修正所有跳转指令 (0x0b JUMP_IF / 0x0c JUMP / 0x10 MENU_SET /
  0x14 INTERRUPT_IF / 0x1c) 的目标地址
- 自动修正 first_offsets (每个 MESSAGE 的入口指针)
- 编码: CP932 (日文编码, 不做 GBK 转换)
  如果游戏需要跑在中文 locale, 走 Locale Emulator 或字体 hook

UI MES (FE ED F1 1B 开头) 和非 .MES 文件会被原样复制.
"""

import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ai5v6_codec import (
    load_mes,
    save_mes,
    is_compressed_story_mes,
    MesScript,
)
from ai5v6_bytecode import disassemble, assemble

ENCODING = 'cp932'


# ---------------------------------------------------------------------------
# 核心注入
# ---------------------------------------------------------------------------

def inject_mes_file(mes_bytes: bytes, entries: list, file_name: str,
                    verbose: bool = False) -> tuple:
    """把译文注入单个 MES 文件, 返回 (新的压缩 MES 字节, 统计字典).
    
    entries: GalTransl JSON 条目 [{name, message, id}, ...]
    id 格式: "FILE.MES#msg_idx#text_idx"
    
    若文件不是剧情 MES (例如 UI MES), 返回 (None, None).
    """
    if not is_compressed_story_mes(mes_bytes):
        return None, None

    script = load_mes(mes_bytes)
    instrs = disassemble(script.bytecode)

    # 建立 id -> 译文 映射
    id_to_translation = {}
    for e in entries:
        name = e.get('name', '') or ''
        message = e.get('message', '') or ''
        translation = name + message   # name 是从 message 拆出来的, 注入时合回去
        id_to_translation[e['id']] = translation

    # 按 MESSAGE block 分组收集 TEXT 指令, 分配 text_idx
    # 每个 MESSAGE (0x17) 开启一个新的 block
    msg_idx = -1
    text_idx = 0

    stats = {
        'total_text': 0,
        'replaced': 0,
        'unchanged': 0,       # JSON 里没有该 id 或译文与原文相同
        'encode_failed': 0,
    }

    for inst in instrs:
        if inst.opcode == 0x17:
            msg_idx += 1
            text_idx = 0
            continue
        if inst.opcode != 0x01:
            continue
        if inst.text is None:
            continue
        # 只处理有日文字符的 TEXT (跟 extract 逻辑一致)
        if not _has_japanese(inst.text):
            continue

        stats['total_text'] += 1
        entry_id = f"{file_name}#{msg_idx}#{text_idx}"
        text_idx += 1

        translation = id_to_translation.get(entry_id)
        if translation is None:
            stats['unchanged'] += 1
            continue

        if translation == inst.text:
            stats['unchanged'] += 1
            continue

        try:
            encoded = translation.encode(ENCODING)
        except UnicodeEncodeError as e:
            stats['encode_failed'] += 1
            if verbose:
                print(f"  [!] {entry_id}: CP932 encode failed at "
                      f"pos {e.start}: {translation[e.start:e.end]!r}",
                      file=sys.stderr)
            continue

        inst.text = translation
        inst.raw = bytes([inst.opcode]) + encoded + b'\x00'
        stats['replaced'] += 1

    # 重组装 bytecode (自动 fixup 所有跳转目标)
    new_bytecode, offset_map = assemble(instrs)

    # 修正 first_offsets
    new_first_offsets = []
    for old_off in script.first_offsets:
        if old_off in offset_map:
            new_first_offsets.append(offset_map[old_off])
        else:
            # 理论上不该发生 — MESSAGE 起点必定是指令边界
            raise RuntimeError(
                f"{file_name}: first_offset 0x{old_off:X} "
                f"not at instruction boundary (bytecode corrupted?)")

    new_script = MesScript(script.message_count, new_first_offsets, new_bytecode)
    return save_mes(new_script), stats


def _has_japanese(s: str) -> bool:
    for c in s:
        if ('\u3040' <= c <= '\u309f' or
            '\u30a0' <= c <= '\u30ff' or
            '\u4e00' <= c <= '\u9fff'):
            return True
    return False


# ---------------------------------------------------------------------------
# 命令行入口
# ---------------------------------------------------------------------------

def cmd_single(mes_in: str, json_path: str, mes_out: str, verbose: bool):
    with open(mes_in, 'rb') as f:
        mes_bytes = f.read()
    with open(json_path, 'r', encoding='utf-8') as f:
        entries = json.load(f)

    file_name = os.path.basename(mes_in)
    result = inject_mes_file(mes_bytes, entries, file_name, verbose=verbose)
    if result[0] is None:
        print(f"[!] {file_name}: not a story MES (UI MES or invalid)")
        return

    new_bytes, stats = result
    with open(mes_out, 'wb') as f:
        f.write(new_bytes)

    print(f"[+] {file_name}: {stats['replaced']}/{stats['total_text']} texts injected")
    if stats['unchanged']:
        print(f"    unchanged: {stats['unchanged']}")
    if stats['encode_failed']:
        print(f"    CP932 encode failed: {stats['encode_failed']}")
    print(f"[+] Output: {mes_out} ({len(new_bytes)} bytes, "
          f"{len(new_bytes) - len(mes_bytes):+d})")


def cmd_batch(mes_in_dir: str, json_dir: str, mes_out_dir: str, verbose: bool):
    os.makedirs(mes_out_dir, exist_ok=True)
    files = sorted(f for f in os.listdir(mes_in_dir)
                   if os.path.isfile(os.path.join(mes_in_dir, f)))

    grand = {'total_text': 0, 'replaced': 0, 'unchanged': 0, 'encode_failed': 0}
    processed = 0
    copied_asis = 0
    no_json = 0

    for fn in files:
        mes_path = os.path.join(mes_in_dir, fn)
        out_path = os.path.join(mes_out_dir, fn)

        with open(mes_path, 'rb') as f:
            mes_bytes = f.read()

        if not fn.upper().endswith('.MES') or not is_compressed_story_mes(mes_bytes):
            # UI MES / .LIB / 其他文件: 原样拷贝
            with open(out_path, 'wb') as f:
                f.write(mes_bytes)
            copied_asis += 1
            continue

        json_name = fn[:-4] + '.json' if fn.upper().endswith('.MES') else fn + '.json'
        json_path = os.path.join(json_dir, json_name)
        if not os.path.exists(json_path):
            # 无 JSON: 原样拷贝
            with open(out_path, 'wb') as f:
                f.write(mes_bytes)
            no_json += 1
            continue

        with open(json_path, 'r', encoding='utf-8') as f:
            entries = json.load(f)

        try:
            new_bytes, stats = inject_mes_file(mes_bytes, entries, fn,
                                               verbose=verbose)
        except Exception as e:
            print(f"  [X] {fn}: FAILED - {e}", file=sys.stderr)
            with open(out_path, 'wb') as f:
                f.write(mes_bytes)
            continue

        with open(out_path, 'wb') as f:
            f.write(new_bytes)

        processed += 1
        for k in grand:
            grand[k] += stats[k]
        if verbose or stats['encode_failed']:
            print(f"  [{processed:3d}] {fn}: "
                  f"{stats['replaced']}/{stats['total_text']} replaced"
                  + (f", {stats['encode_failed']} encode failed"
                     if stats['encode_failed'] else ""))

    print(f"\n[+] Injected: {processed} files")
    print(f"[+] Total texts: {grand['total_text']} "
          f"({grand['replaced']} replaced, "
          f"{grand['unchanged']} unchanged, "
          f"{grand['encode_failed']} encode failed)")
    print(f"[+] Copied as-is: {copied_asis} files (UI MES / other)")
    if no_json:
        print(f"[+] No JSON: {no_json} files (copied as-is)")


def cmd_verify(mes_in: str):
    """反汇编 -> 原样重组装, 验证工具链对该文件无损."""
    with open(mes_in, 'rb') as f:
        mes_bytes = f.read()

    file_name = os.path.basename(mes_in)
    if not is_compressed_story_mes(mes_bytes):
        print(f"[!] {file_name}: UI MES, not supported by this tool")
        return

    script = load_mes(mes_bytes)
    instrs = disassemble(script.bytecode)
    new_bytecode, offset_map = assemble(instrs)

    print(f"[+] {file_name}")
    print(f"    Instructions: {len(instrs)}")
    print(f"    Free bytes: {sum(1 for i in instrs if i.is_free_byte)}")
    print(f"    Jumps: {sum(1 for i in instrs if i.jump_target is not None)}")
    print(f"    Messages: {script.message_count}")

    if new_bytecode == script.bytecode:
        print(f"    Round-trip: BYTE-IDENTICAL ✓")
    else:
        print(f"    Round-trip: DIFFERS ({len(script.bytecode)} vs {len(new_bytecode)})")
        for i in range(min(len(new_bytecode), len(script.bytecode))):
            if new_bytecode[i] != script.bytecode[i]:
                print(f"    First diff at 0x{i:X}: "
                      f"orig=0x{script.bytecode[i]:02X} new=0x{new_bytecode[i]:02X}")
                break


def main():
    ap = argparse.ArgumentParser(description='AI5WIN V6 MES text injector')
    ap.add_argument('-v', '--verbose', action='store_true')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_single = sub.add_parser('single', help='Inject single MES file')
    p_single.add_argument('mes_in')
    p_single.add_argument('json_path')
    p_single.add_argument('mes_out')

    p_batch = sub.add_parser('batch', help='Batch inject directory')
    p_batch.add_argument('mes_in_dir')
    p_batch.add_argument('json_dir')
    p_batch.add_argument('mes_out_dir')

    p_verify = sub.add_parser('verify', help='Verify disassembler round-trip')
    p_verify.add_argument('mes_in')

    args = ap.parse_args()
    if args.cmd == 'single':
        cmd_single(args.mes_in, args.json_path, args.mes_out, args.verbose)
    elif args.cmd == 'batch':
        cmd_batch(args.mes_in_dir, args.json_dir, args.mes_out_dir, args.verbose)
    elif args.cmd == 'verify':
        cmd_verify(args.mes_in)


if __name__ == '__main__':
    main()
