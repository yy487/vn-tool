#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scr_extract.py  —  Studio e.go!/TwinWay BSF1 脚本文本提取器

从 .scr 里抽出 CP932 台词 (混在 opcode 流里的裸 cstring), 附带前置
SPEAKER 指令指定的说话人, 输出 GalTransl 风格 JSON:

    [
      {"id": 0, "pc": "0x578", "name": "僚", "message": "「明日は筋肉痛かもな……」"},
      ...
    ]

pc 字段保留是为了注入阶段做稳定匹配 (变长注入不能靠 id, 因为翻译时
条目顺序可能被工具改动)。

用法:
    python scr_extract.py extract Daytalk.scr daytalk.json
    python scr_extract.py batch   indir/       outdir/
    python scr_extract.py disasm  Daytalk.scr               # 人读反汇编
"""
import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bsf1_codec import disasm_all, ParseError


# ---- 单文件提取 ----------------------------------------------------------

# SPEAKER 语义 (来自 tw.exe case 2 + FUN_00416168):
#   - SPEAKER "<name>" → DAT_004372e0 = "<name>", 画面显示独立姓名框
#   - SPEAKER "*"      → DAT_004372e0 = DAT_00438298 (**全 0 BSS**) = 空字符串
#                        即清空姓名, 之后文本作为旁白显示
#   - WAIT 不清空 speaker (case 3 只重置文本行计数, 不碰 DAT_004372e0)
#   - case 0x12 (MENU) 会直接 DAT_004372e0 = 0 清空
#
# 所以追踪规则:
#   - 见到 SPEAKER '非*' → cur_speaker = 该 name
#   - 见到 SPEAKER '*'   → cur_speaker = None
#   - 见到 MENU          → cur_speaker = None
#   - WAIT / JUMP / CALL / SELECT 都不影响 (speaker 持续到下一次 SPEAKER)
SPEAKER_CLEAR_OPS = {
    'MENU',   # case 0x12 显式 DAT_004372e0 = 0
}


def extract_file(scr_path: str) -> list:
    data = open(scr_path, 'rb').read()
    _, _, _, insns, _ = disasm_all(data)

    entries = []
    cur_speaker = None
    tid = 0
    for insn in insns:
        kind = insn['kind']
        if kind == 'op':
            name = insn['name']
            if name == 'SPEAKER':
                raw = insn['args'][0]
                if raw == b'*':
                    # '*' = DAT_00438298 (空 BSS) = 清空 speaker
                    cur_speaker = None
                else:
                    try:
                        cur_speaker = raw.decode('cp932')
                    except Exception:
                        cur_speaker = raw.decode('cp932', errors='replace')
                continue
            if name in SPEAKER_CLEAR_OPS:
                cur_speaker = None
            continue

        # kind == 'text'
        try:
            msg = insn['text'].decode('cp932')
        except Exception:
            msg = insn['text'].decode('cp932', errors='replace')
        item = {
            'id': tid,
            'pc': f'0x{insn["pc"]:x}',
        }
        if cur_speaker:
            item['name'] = cur_speaker
        item['message'] = msg
        entries.append(item)
        tid += 1
    return entries


def cmd_extract(args):
    entries = extract_file(args.scr)
    if not entries:
        print(f'[-] {args.scr}: 无文本, 跳过')
        return
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f'[✓] {args.scr}: {len(entries)} 条文本 → {args.out}')


def cmd_batch(args):
    os.makedirs(args.outdir, exist_ok=True)
    total_files = 0
    total_texts = 0
    skipped_empty = 0
    failed = []
    for root, _, files in os.walk(args.indir):
        for fn in files:
            if not fn.lower().endswith('.scr'):
                continue
            scr_path = os.path.join(root, fn)
            rel = os.path.relpath(scr_path, args.indir)
            out_name = os.path.splitext(rel)[0] + '.json'
            out_path = os.path.join(args.outdir, out_name)
            try:
                entries = extract_file(scr_path)
            except (ParseError, Exception) as e:
                failed.append((scr_path, str(e)))
                print(f'[!] {rel}: {e}')
                continue
            if not entries:
                skipped_empty += 1
                continue
            os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(entries, f, ensure_ascii=False, indent=2)
            total_files += 1
            total_texts += len(entries)
            if total_files % 20 == 0:
                print(f'  [{total_files}] {rel}: {len(entries)}')
    print(f'\n✓ 批量提取完成: {total_files} 个 JSON, '
          f'{total_texts} 条文本, 跳过 {skipped_empty} 个空脚本')
    if failed:
        print(f'✗ {len(failed)} 个文件失败:')
        for p, e in failed[:10]:
            print(f'   {p}: {e}')


# ---- 反汇编 (调试用) -----------------------------------------------------

def _fmt_arg(v):
    if isinstance(v, bytes):
        try:
            return repr(v.decode('cp932'))
        except Exception:
            return v.hex()
    return f'{v:#x}' if isinstance(v, int) and v > 9 else str(v)


def cmd_disasm(args):
    data = open(args.scr, 'rb').read()
    labels, bc_start, pc_to_labels, insns, trailer = disasm_all(data)
    print(f'; {args.scr}')
    print(f'; labels: {len(labels)}, bc_start: {bc_start:#x}, insns: {len(insns)}'
          + (f', trailer: {len(trailer)}B' if trailer else ''))
    print()
    for insn in insns:
        pc = insn['pc']
        for lbl in pc_to_labels.get(pc, []):
            try:
                s = lbl.decode('cp932')
            except Exception:
                s = lbl.hex()
            print(f'{s}:')
        if insn['kind'] == 'text':
            try:
                s = insn['text'].decode('cp932')
            except Exception:
                s = insn['text'].hex()
            print(f'  {pc:06x}  TEXT    {s!r}')
        else:
            args_s = ', '.join(_fmt_arg(a) for a in insn['args'])
            print(f"  {pc:06x}  {insn['name']:<16} {args_s}")


# ---- CLI ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='Studio e.go!/TwinWay BSF1 脚本文本提取器')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract', help='提取单个 .scr 到 JSON')
    p.add_argument('scr')
    p.add_argument('out')
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser('batch', help='批量提取目录')
    p.add_argument('indir')
    p.add_argument('outdir')
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser('disasm', help='反汇编到 stdout (调试用)')
    p.add_argument('scr')
    p.set_defaults(func=cmd_disasm)

    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
