#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 GalTransl JSON 中所有用到的字符，输出 charset.json。

新版要点：
- 默认扫描 name/message 字段。
- 默认先执行 text_normalize.normalize_text，再统计字符。
- 不再默认加入 ASCII。是否全角化由 normalize_text 控制。

用法:
  python scan_chars.py <json_dir> [output.json]
  python scan_chars.py <single.json> [output.json]
  python scan_chars.py trans_json build/charset.json --fields name,message
"""
import argparse
import glob
import json
import os

from text_normalize import normalize_text


def scan_file(path, charset, fields, do_normalize=True):
    with open(path, 'r', encoding='utf-8') as f:
        entries = json.load(f)
    for e in entries:
        if not isinstance(e, dict):
            continue
        for field in fields:
            text = e.get(field, '')
            if not isinstance(text, str):
                continue
            if do_normalize:
                text = normalize_text(text)
            charset.update(text)


def main():
    ap = argparse.ArgumentParser(description='scan translated json chars for AI5WIN font build')
    ap.add_argument('src')
    ap.add_argument('out', nargs='?', default='charset.json')
    ap.add_argument('--fields', default='name,message')
    ap.add_argument('--no-normalize', action='store_true')
    ap.add_argument('--include-newline', action='store_true')
    args = ap.parse_args()

    fields = [x.strip() for x in args.fields.split(',') if x.strip()]
    charset = set()

    if os.path.isdir(args.src):
        files = sorted(glob.glob(os.path.join(args.src, '*.json')))
        for path in files:
            if os.path.basename(path).startswith('_'):
                continue
            scan_file(path, charset, fields, do_normalize=not args.no_normalize)
        print(f"扫描 {len(files)} 个文件")
    else:
        scan_file(args.src, charset, fields, do_normalize=not args.no_normalize)

    charset.discard('')
    if not args.include_newline:
        charset.discard('\n')
    chars = sorted(charset, key=lambda c: ord(c))
    result = {
        'version': 1,
        'normalized': not args.no_normalize,
        'fields': fields,
        'total': len(chars),
        'chars': chars,
    }
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    cjk = sum(1 for c in chars if '\u4e00' <= c <= '\u9fff')
    kana = sum(1 for c in chars if '\u3040' <= c <= '\u30ff')
    ascii_count = sum(1 for c in chars if '\u0020' <= c <= '\u007e')
    other = len(chars) - cjk - kana - ascii_count
    print(f"字符数: {len(chars)} → {args.out}")
    print(f"  CJK汉字: {cjk}, 假名: {kana}, ASCII: {ascii_count}, 其他: {other}")


if __name__ == '__main__':
    main()
