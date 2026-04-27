#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_json.py — 把旧版 (MENU_INIT bug 版反汇编器) 提取的翻译 JSON
与新版 (修复后) 提取的 JSON 合并.

背景:
  旧版 ai5v7_bytecode_v2.py 把 MENU_INIT 的 u16 skip target 错误识别成
  独立的 TEXT2/SJIS/JUMP 指令, 导致指令流里多出"幽灵指令", msg_insn_idx
  基于旧指令流编号. 修复后指令数量变化, 旧下标全部失效, inject 会报
  "insn[xxx] 不是 TEXT 指令".

做法:
  1. 对每个 MES 用新版 extract 生成新 JSON (带正确的 _meta)
  2. 按 id 字段把旧 JSON 的 message (翻译文) 拷到新 JSON 上
  3. 丢弃旧 JSON 里但新 JSON 里没有的条目 (误识别, 翻译无效)
  4. 新 JSON 里没有在旧 JSON 里出现的条目 → 保留日文原文, 标记为未翻译

用法:
  python merge_json.py <orig_mes_dir> <old_json_dir> <new_out_dir>

  orig_mes_dir: 原始 MES 解包目录
  old_json_dir: 你之前翻译好的旧 JSON 目录
  new_out_dir:  输出合并后的新 JSON 目录 (inject 用这个)
"""
import os, sys, json

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)
from ai5v7_bytecode_v2 import lzss_decompress, disassemble, OPCODES
from ai5winv7_mes_extract import extract_messages

# 确认是修复版
assert OPCODES[0x0E][1] == 'CVH', (
    f'ai5v7_bytecode_v2.py 必须是修复版 (CVH)! 当前: {OPCODES[0x0E]}'
)


def extract_new(mes_path):
    """用修复版反汇编器重新提取 MES, 返回新的消息列表."""
    raw = open(mes_path, 'rb').read()
    plain = lzss_decompress(raw)
    insns = disassemble(plain)
    return extract_messages(insns, os.path.basename(mes_path))


def merge_one(mes_path, old_json_path):
    """合并单个 MES 的新旧 JSON, 返回合并后的列表 + 统计."""
    new_entries = extract_new(mes_path)
    if not os.path.exists(old_json_path):
        # 旧 JSON 不存在 → 全部作为未翻译保留
        return new_entries, {
            'matched': 0,
            'untranslated': len(new_entries),
            'orphan_old': 0,
        }

    with open(old_json_path, 'r', encoding='utf-8') as f:
        old_entries = json.load(f)

    # 按 id 建立旧 entry 的索引 (id → message)
    old_by_id = {}
    for e in old_entries:
        old_by_id[e['id']] = {
            'message': e.get('message', ''),
            'name': e.get('name', ''),
        }

    # 遍历新 entries, 填入旧 message
    matched = 0
    untranslated = 0
    new_ids = set()
    for e in new_entries:
        new_ids.add(e['id'])
        if e['id'] in old_by_id:
            old = old_by_id[e['id']]
            # 如果旧 message 和新 message (日文原文) 相同, 说明没翻译
            if old['message'] == e['message']:
                untranslated += 1
            else:
                e['message'] = old['message']
                matched += 1
            # name 字段也用旧值 (翻译版)
            if old['name']:
                e['name'] = old['name']
        else:
            untranslated += 1

    # 统计旧 JSON 里的 orphan (id 在新 JSON 中不存在)
    orphan_old = sum(1 for old_id in old_by_id if old_id not in new_ids)

    return new_entries, {
        'matched': matched,
        'untranslated': untranslated,
        'orphan_old': orphan_old,
    }


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    mes_dir, old_json_dir, out_dir = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)

    files = sorted(f for f in os.listdir(mes_dir) if f.upper().endswith('.MES'))
    total_matched = 0
    total_untranslated = 0
    total_orphan = 0
    total_new_entries = 0
    skipped_empty = 0
    no_old_json = []

    summary = []
    for fn in files:
        mes_path = os.path.join(mes_dir, fn)
        stem = fn.rsplit('.', 1)[0]
        old_json_path = os.path.join(old_json_dir, stem + '.json')
        out_json_path = os.path.join(out_dir, stem + '.json')

        try:
            merged, stats = merge_one(mes_path, old_json_path)
        except Exception as e:
            print(f'  {fn}: ERROR {e}')
            continue

        if not merged:
            skipped_empty += 1
            continue

        with open(out_json_path, 'w', encoding='utf-8') as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)

        total_new_entries += len(merged)
        total_matched += stats['matched']
        total_untranslated += stats['untranslated']
        total_orphan += stats['orphan_old']

        if not os.path.exists(old_json_path):
            no_old_json.append(fn)
            continue

        # 只打印有差异的文件
        if stats['untranslated'] > 0 or stats['orphan_old'] > 0:
            summary.append(
                (fn, len(merged), stats['matched'],
                 stats['untranslated'], stats['orphan_old'])
            )

    print(f'\n=== 合并结果 ===')
    print(f'处理文件: {len(files)}')
    print(f'空 MES 跳过: {skipped_empty}')
    print(f'无旧 JSON (全部未翻译): {len(no_old_json)}')
    print()
    print(f'新提取总消息数: {total_new_entries}')
    print(f'成功合并翻译: {total_matched}')
    print(f'未翻译 (保留日文): {total_untranslated}')
    print(f'旧 JSON 残留 orphan (已丢弃): {total_orphan}')
    print()

    if summary:
        print(f'--- 有差异的文件 ({len(summary)}) ---')
        print(f'  {"FILENAME":20} {"TOTAL":>6} {"MATCHED":>8} '
              f'{"UNTRANS":>8} {"ORPHAN":>8}')
        for fn, tot, m, u, o in sorted(summary, key=lambda x: -x[4]-x[3])[:40]:
            print(f'  {fn:20} {tot:6d} {m:8d} {u:8d} {o:8d}')
        if len(summary) > 40:
            print(f'  ... 还有 {len(summary)-40} 个')

    if no_old_json:
        print(f'\n--- 无旧 JSON 的文件 ({len(no_old_json)}, 前 10) ---')
        for fn in no_old_json[:10]:
            print(f'  {fn}')
        if len(no_old_json) > 10:
            print(f'  ... 还有 {len(no_old_json)-10} 个')


if __name__ == '__main__':
    main()
