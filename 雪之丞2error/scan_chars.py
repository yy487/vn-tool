#!/usr/bin/env python3
"""扫描 GalTransl JSON 中所有用到的字符，输出字符集 JSON。

用法:
  python scan_chars.py <json_dir> [output.json]
  python scan_chars.py <single.json> [output.json]

输出格式:
  {
    "total": 2345,
    "chars": ["　", "、", "。", "「", ... ]
  }

字符按 Unicode 码点排序，自动包含基础标点和ASCII可打印字符。
"""
import json, sys, os, glob

def scan_file(path, charset):
    with open(path, 'r', encoding='utf-8') as f:
        entries = json.load(f)
    for e in entries:
        for field in ('name', 'message'):
            text = e.get(field, '')
            if isinstance(text, str):
                charset.update(text)

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)

    src = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else 'charset.json'

    charset = set()

    # 基础字符: ASCII 可打印 + 全角空格 + 常用标点
    for c in range(0x20, 0x7F):
        charset.add(chr(c))
    charset.add('　')  # 全角空格

    if os.path.isdir(src):
        files = sorted(glob.glob(os.path.join(src, '*.json')))
        for f in files:
            if os.path.basename(f).startswith('_'):
                continue
            scan_file(f, charset)
        print(f"扫描 {len(files)} 个文件")
    else:
        scan_file(src, charset)

    # 去掉空字符串
    charset.discard('')

    chars = sorted(charset, key=lambda c: ord(c))

    result = {"total": len(chars), "chars": chars}
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"字符数: {len(chars)} → {out_path}")

    # 统计
    cjk = sum(1 for c in chars if '\u4e00' <= c <= '\u9fff')
    kana = sum(1 for c in chars if '\u3040' <= c <= '\u30ff')
    ascii_count = sum(1 for c in chars if '\u0020' <= c <= '\u007e')
    other = len(chars) - cjk - kana - ascii_count
    print(f"  CJK汉字: {cjk}, 假名: {kana}, ASCII: {ascii_count}, 其他: {other}")

if __name__ == '__main__':
    main()
