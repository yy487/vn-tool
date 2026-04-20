#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai5winv7_mes_extract.py — V7 (愛しの言霊) MES → GalTransl JSON 提取

流程:
  1. LZSS 解压 (ai5v7_bytecode_v2.lzss_decompress)
  2. 反汇编为指令流 (disassemble)
  3. 识别 TEXT (op 0x01) 指令, 按 (NAME, NEW_LINE, DIAL) 三元组配对 name/message
  4. 输出 GalTransl 兼容的 JSON

角色名识别规则 (在 475 个候选 / 8 个样本上零误判验证通过):
  一条 TEXT 被视为角色名 ⇔ 满足全部:
    1. 字节长度 ≤ 12 (约 6 个 SJIS 字符)
    2. 解码 cp932 后不含 「 或 。
    3. 紧邻下一条指令是 NEW_LINE (op 0x11)
    4. 再下一条 (非 NL) 是 TEXT 对白
  抓到的名字:薫/清美/理恵/義平/無道 + 描述性 (間延びした声/女の子 等)
  主角对白无 name (AI5 惯例), 独立 message 条目

跳过 (不作为翻译条目, 原样保留):
  - TEXT_SYS (op 0x02) — 全部样本内容固定 07ff026ea0, 是 page break 控制
  - TEXT2 <ff> 隐式 run — 紧跟 TEXT_SYS, page break 的一部分

id 格式:
  "FILENAME#idx"  (idx 为 0 基, 按文件内 message 序号累加)

JSON 字段 (GalTransl 标准):
  name:    角色名 (无则空串)
  message: 待翻译文本 (日文 CP932 解码后)
  id:      唯一标识
  _meta:   (可选) inject 所需的指令位置信息, extract 时保留, translate 后可丢弃

用法:
  ai5winv7_mes_extract.py single <mes_path> <json_out>
  ai5winv7_mes_extract.py batch  <mes_dir>  <json_dir>
"""
import os
import sys
import json
import argparse

# 依赖同目录的反汇编器
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
from ai5v7_bytecode_v2 import lzss_decompress, disassemble


# ---------------------------------------------------------------------------
# Name 识别
# ---------------------------------------------------------------------------
NAME_MAX_BYTES = 12


def looks_like_name(text_bytes):
    """判定一条 TEXT 是否可能是角色名.
    规则: 长度 ≤ 12 字节, 不含 「/。, 能 CP932 解码."""
    if len(text_bytes) == 0 or len(text_bytes) > NAME_MAX_BYTES:
        return False
    try:
        s = text_bytes.decode('cp932')
    except UnicodeDecodeError:
        return False
    if '「' in s or '。' in s:
        return False
    return True


# ---------------------------------------------------------------------------
# 核心提取
# ---------------------------------------------------------------------------
def extract_messages(insns, filename):
    """从指令流提取 message 列表.

    返回: list of dict, 每项包含
      name:    str
      message: str
      id:      str ("FILE#N")
      _meta:   dict,  {
                 'name_insn_idx': int|None,   # NAME TEXT 在 insns 中的下标
                 'msg_insn_idx':  int,         # 对白/叙事 TEXT 在 insns 中的下标
               }
    """
    results = []
    msg_counter = 0
    n = len(insns)
    i = 0

    while i < n:
        insn = insns[i]
        if not (insn[0] == 'OP' and insn[2] == 0x01):
            i += 1
            continue

        text_bytes = insn[4][0]
        # 候选 NAME 检查
        name_candidate = False
        if i + 2 < n and looks_like_name(text_bytes):
            nl = insns[i + 1]
            dlg = insns[i + 2]
            if (nl[0] == 'OP' and nl[2] == 0x11 and
                dlg[0] == 'OP' and dlg[2] == 0x01):
                name_candidate = True

        if name_candidate:
            dlg_bytes = insns[i + 2][4][0]
            try:
                name_s = text_bytes.decode('cp932')
                msg_s = dlg_bytes.decode('cp932')
            except UnicodeDecodeError:
                # 异常, 不配对, 只输出当前 TEXT
                _emit_solo(results, text_bytes, filename, msg_counter, i)
                msg_counter += 1
                i += 1
                continue

            results.append({
                'name': name_s,
                'message': msg_s,
                'id': f'{filename}#{msg_counter}',
                '_meta': {
                    'name_insn_idx': i,
                    'msg_insn_idx':  i + 2,
                },
            })
            msg_counter += 1
            i += 3
            continue

        # 独立 TEXT (主角对白 / 叙事 / 独白)
        _emit_solo(results, text_bytes, filename, msg_counter, i)
        msg_counter += 1
        i += 1

    return results


def _emit_solo(results, text_bytes, filename, counter, idx):
    try:
        s = text_bytes.decode('cp932')
    except UnicodeDecodeError:
        # 用 lossy 解码保证有输出, inject 时注意不能依赖它
        s = text_bytes.decode('cp932', errors='replace')
    results.append({
        'name': '',
        'message': s,
        'id': f'{filename}#{counter}',
        '_meta': {
            'name_insn_idx': None,
            'msg_insn_idx':  idx,
        },
    })


# ---------------------------------------------------------------------------
# 单文件/批量
# ---------------------------------------------------------------------------
def extract_one(mes_path):
    raw = open(mes_path, 'rb').read()
    plain = lzss_decompress(raw)
    insns = disassemble(plain)
    filename = os.path.basename(mes_path)
    return extract_messages(insns, filename)


def cmd_single(mes_path, json_out):
    results = extract_one(mes_path)
    os.makedirs(os.path.dirname(os.path.abspath(json_out)) or '.', exist_ok=True)
    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    total = len(results)
    named = sum(1 for r in results if r['name'])
    unique_names = sorted({r['name'] for r in results if r['name']})
    print(f'{mes_path}: {total} messages ({named} named) → {json_out}')
    if unique_names:
        print(f'  角色名 ({len(unique_names)}): {", ".join(unique_names)}')


def cmd_batch(mes_dir, json_dir):
    os.makedirs(json_dir, exist_ok=True)
    files = sorted(f for f in os.listdir(mes_dir) if f.upper().endswith('.MES'))
    total_msgs = 0
    total_named = 0
    all_names = {}
    failed = []
    empty_skipped = []   # 没有任何 TEXT 的 MES, 不写 JSON

    for fn in files:
        mes_path = os.path.join(mes_dir, fn)
        try:
            results = extract_one(mes_path)
        except Exception as e:
            failed.append((fn, str(e)[:80]))
            continue

        if not results:
            # 空 JSON: 该 MES 里没有任何 TEXT 指令, 没有可翻译内容
            # 直接跳过, 不写文件, 避免污染 json 目录
            empty_skipped.append(fn)
            continue

        json_path = os.path.join(json_dir, fn.rsplit('.', 1)[0] + '.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        total_msgs += len(results)
        total_named += sum(1 for r in results if r['name'])
        for r in results:
            if r['name']:
                all_names[r['name']] = all_names.get(r['name'], 0) + 1

    print(f'\n=== 批量提取结果 ===')
    print(f'处理: {len(files) - len(failed)} / {len(files)} 个 MES')
    print(f'写出 JSON: {len(files) - len(failed) - len(empty_skipped)} 个')
    print(f'跳过 (无文本): {len(empty_skipped)} 个')
    print(f'总消息数: {total_msgs}')
    print(f'带角色名: {total_named}')
    if all_names:
        print(f'\n角色名合集 (按出现次数):')
        for n, c in sorted(all_names.items(), key=lambda x: -x[1]):
            print(f'  {n!r}: {c}')
    if empty_skipped:
        print(f'\n跳过的空文件 (前 30 个):')
        for fn in empty_skipped[:30]:
            print(f'  {fn}')
        if len(empty_skipped) > 30:
            print(f'  ... 还有 {len(empty_skipped) - 30} 个')
    if failed:
        print(f'\n失败 ({len(failed)}):')
        for fn, err in failed[:20]:
            print(f'  {fn}: {err}')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description='AI5WIN V7 MES → GalTransl JSON 提取',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('single', help='单文件提取')
    p1.add_argument('mes_path')
    p1.add_argument('json_out')

    p2 = sub.add_parser('batch', help='批量提取整个目录')
    p2.add_argument('mes_dir')
    p2.add_argument('json_dir')

    args = ap.parse_args()
    if args.cmd == 'single':
        cmd_single(args.mes_path, args.json_out)
    elif args.cmd == 'batch':
        cmd_batch(args.mes_dir, args.json_dir)


if __name__ == '__main__':
    main()
