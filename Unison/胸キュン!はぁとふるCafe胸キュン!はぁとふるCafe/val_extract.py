#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lazy 引擎 .VAL 剧情文本提取工具
================================

用法:
    python3 val_extract.py <input_dir> <output_dir>

行为:
    遍历 <input_dir> 下所有 .VAL 文件, 仅对剧情脚本 (classify_val == 'story')
    提取由 0xdd opcode 引用、且内容含日文/日式标点的字符串.

    每个剧情脚本输出一份 GalTransl 兼容 JSON:
        [
          {"name": "", "message": "日文文本"},
          ...
        ]

    JSON 顺序 = seg_A 中 dd 站点出现顺序 (= 剧情时间线).
    同一字符串在 seg_B 中若被多个站点引用, 也会在 JSON 里出现多次;
    GalTransl 翻译时会自动去重保持一致.

    每条记录额外携带 _site / _idx 两个内部字段, 用于 inject 阶段精确回写.
"""
import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lazy_common import (
    ValFile, classify_val, collect_story_refs, decode_sjis,
)


def extract_one(val_path: str, out_json_path: str) -> dict:
    with open(val_path, 'rb') as f:
        data = f.read()
    v = ValFile.parse(data)
    refs = collect_story_refs(v)

    items = []
    for site, idx in refs:
        items.append({
            'name': '',
            'message': decode_sjis(v.strings[idx]),
            # 内部对账字段; GalTransl 不动它们, inject 时按这两个字段精确回写
            '_site': site,
            '_idx': idx,
        })

    with open(out_json_path, 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False, indent=2)

    return {
        'val': os.path.basename(val_path),
        'json': os.path.basename(out_json_path),
        'ref_count': len(refs),
        'distinct_idx': len({idx for _, idx in refs}),
        'string_count': len(v.strings),
        'seg_a_size': len(v.seg_a),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input_dir',  help='解包后的 .VAL 目录 (包含 _vct_meta.json)')
    ap.add_argument('output_dir', help='输出 JSON 目录')
    args = ap.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    summary = {'story': [], 'system_skipped': []}
    total_refs = 0

    for fname in sorted(os.listdir(args.input_dir)):
        if fname.startswith('_'):
            continue
        path = os.path.join(args.input_dir, fname)
        if not os.path.isfile(path) or not fname.upper().endswith('.VAL'):
            continue

        name_no_ext = os.path.splitext(fname)[0]
        if classify_val(name_no_ext) != 'story':
            summary['system_skipped'].append(fname)
            continue

        out_json = os.path.join(args.output_dir, name_no_ext + '.json')
        try:
            info = extract_one(path, out_json)
        except Exception as e:
            print(f"  [ERR] {fname}: {e}")
            continue
        summary['story'].append(info)
        total_refs += info['ref_count']

    summary['totals'] = {
        'story_files':     len(summary['story']),
        'system_skipped':  len(summary['system_skipped']),
        'total_text_refs': total_refs,
    }
    with open(os.path.join(args.output_dir, '_extract_index.json'), 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[OK] story={len(summary['story'])}, "
          f"system_skipped={len(summary['system_skipped'])}, "
          f"total_text_refs={total_refs}")
    print(f"     output -> {args.output_dir}")


if __name__ == '__main__':
    main()
