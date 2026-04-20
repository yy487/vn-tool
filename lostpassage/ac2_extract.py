#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ac2_extract.py —— AdvSystem 脚本文本提取

用法:
    python ac2_extract.py <script_dir> <output.json>

输入:
    script_dir: ac2_tool.py unpack 解出的脚本目录 (含 DATA/SCRIPT/*.TXT 等)

输出 JSON (GalTransl 兼容):
    [
        {
            "message_id": 0,
            "name":       "育美",          // 对话才有, 叙述/选项为空串
            "message":    "...",            // 待翻译原文
            "_file":      "DATA/SCRIPT/00110.TXT",
            "_line":      42,
            "_kind":      "dialogue"        // dialogue | narration | answer
        },
        ...
    ]

策略:
    - 空文件跳过 (0 字节或无可翻译行都跳过)
    - 行分类规则见 ac2_common.py
    - 对话文本含引号「」整段提取 (译文同样要整段, 注入时原样替换)
"""

import os
import sys
import json
import argparse

from ac2_common import (
    iter_classified_lines,
    read_script,
    iter_scripts,
)


def extract_file(abs_path, rel_path, start_id):
    """
    提取单个脚本文件
    返回 (entries, next_id)
    """
    try:
        lines, eol, trailing_eol = read_script(abs_path)
    except Exception as e:
        print(f'  [error] {rel_path}: 读取失败 ({e})', file=sys.stderr)
        return [], start_id

    if not lines:
        return [], start_id

    entries = []
    mid = start_id
    for lineno, kind, info in iter_classified_lines(lines):
        if kind is None:
            continue
        name = info.get('name', '') if kind == 'dialogue' else ''
        text = info['text']
        entries.append({
            'message_id': mid,
            'name': name,
            'message': text,
            '_file': rel_path,
            '_line': lineno,
            '_kind': kind,
        })
        mid += 1
    return entries, mid


def main():
    ap = argparse.ArgumentParser(description='AdvSystem 脚本提取')
    ap.add_argument('script_dir', help='脚本目录 (ac2 解包产物)')
    ap.add_argument('output_json', help='输出 JSON 路径')
    args = ap.parse_args()

    if not os.path.isdir(args.script_dir):
        print(f'错误: 目录不存在 {args.script_dir}', file=sys.stderr)
        sys.exit(1)

    all_entries = []
    file_count = 0
    skipped = 0
    next_id = 0
    stat_kind = {'dialogue': 0, 'narration': 0, 'answer': 0}

    for abs_path, rel_path in iter_scripts(args.script_dir):
        file_count += 1
        # 空文件跳过
        if os.path.getsize(abs_path) == 0:
            print(f'  [skip] {rel_path}: 空文件')
            skipped += 1
            continue

        entries, next_id = extract_file(abs_path, rel_path, next_id)
        if not entries:
            print(f'  [skip] {rel_path}: 无可翻译行')
            skipped += 1
            continue

        for e in entries:
            stat_kind[e['_kind']] += 1
        all_entries.extend(entries)

    # 输出
    os.makedirs(os.path.dirname(args.output_json) or '.', exist_ok=True)
    with open(args.output_json, 'w', encoding='utf-8') as f:
        json.dump(all_entries, f, ensure_ascii=False, indent=2)

    print()
    print(f'扫描文件: {file_count}, 跳过: {skipped}')
    print(f'提取条目: {len(all_entries)}')
    print(f'  dialogue : {stat_kind["dialogue"]}')
    print(f'  narration: {stat_kind["narration"]}')
    print(f'  answer   : {stat_kind["answer"]}')
    print(f'输出: {args.output_json}')


if __name__ == '__main__':
    main()
