#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ac2_inject.py —— AdvSystem 脚本文本回填

用法:
    python ac2_inject.py <source_dir> <trans.json> <output_dir>

输入:
    source_dir : 原始脚本目录 (ac2_tool.py 解出的日文脚本)
    trans.json : ac2_extract.py 生成的 JSON, 其中 message 字段已被替换为译文
    output_dir : 输出目录 (保留原 DATA/SCRIPT/... 结构)

行为:
    1. 按 _file + _line 定位, 只替换对应行的文本段 (dialogue 保留 name, answer 保留 ', #target')
    2. 其它行原样保留
    3. JSON 中没有条目的源文件 → 原样复制到 output_dir (包括 manifest.json 等)
    4. 译文为空字符串时, 该条保留原文 (便于翻译进度中间产物也能注入)
    5. 译文无法 cp932 编码时, 报错并保留原文该行, 继续处理后续条目

注入后可用 ac2_tool.py repack output_dir/ Data_cn.ac2 打包回 .ac2
"""

import os
import sys
import json
import argparse
from collections import defaultdict

from ac2_common import (
    classify_line,
    iter_classified_lines,
    rebuild_line,
    read_script,
    write_script,
    iter_scripts,
    copy_file,
    ENCODING as SRC_ENCODING,
)


def load_translations(json_path):
    """
    读取译文 JSON
    返回: { rel_file: { lineno: entry } }
    """
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    by_file = defaultdict(dict)
    for e in data:
        by_file[e['_file']][e['_line']] = e
    return by_file


def inject_file(abs_path, rel_path, line_map, out_path, stats, out_encoding):
    """
    处理单个脚本文件
    line_map: { lineno: entry } 该文件的译文表
    out_encoding: 译文行使用的编码 (cp932 / gbk 等)

    策略:
        - 按字节保留未翻译的行 (原样 CP932 字节流)
        - 只对翻译过的行用 out_encoding 编码
        - 这样可避开原文指令行里 GBK 不支持的字符 (如 ・ U+30FB)
    """
    with open(abs_path, 'rb') as f:
        raw = f.read()

    # 检测行尾
    eol_bytes = b'\r\n' if b'\r\n' in raw else b'\n'
    # 拆分字节行, 保留末尾空行特征
    lines_b = raw.split(eol_bytes)
    trailing_eol = False
    if lines_b and lines_b[-1] == b'':
        lines_b.pop()
        trailing_eol = True

    # 用源字节先解码为字符串列表 (为了续行感知需要看到整个文件上下文)
    src_lines_s = []
    for raw_b in lines_b:
        try:
            src_lines_s.append(raw_b.decode(SRC_ENCODING))
        except UnicodeDecodeError:
            src_lines_s.append(raw_b.decode(SRC_ENCODING, errors='replace'))
            stats['src_decode_fail'] += 1

    # 续行感知分类
    for lineno, kind, info in iter_classified_lines(src_lines_s):
        if lineno not in line_map:
            continue

        entry = line_map[lineno]
        if kind is None:
            stats['line_classify_mismatch'] += 1
            print(f'  [warn] {rel_path}:{lineno} 行被判为不翻译(空行/注释/指令/续行), '
                  f'但 JSON 有条目 (_kind={entry["_kind"]}), 跳过', file=sys.stderr)
            continue
        if kind != entry['_kind']:
            stats['kind_mismatch'] += 1
            print(f'  [warn] {rel_path}:{lineno} 种类不匹配: '
                  f'实际={kind}, JSON={entry["_kind"]}, 跳过', file=sys.stderr)
            continue

        new_text = entry.get('message', '')
        if not new_text:
            stats['empty_kept'] += 1
            continue

        new_line = rebuild_line(kind, info, new_text)
        try:
            lines_b[lineno - 1] = new_line.encode(out_encoding)
            stats['injected'] += 1
        except UnicodeEncodeError as e:
            stats['encode_fail'] += 1
            print(f'  [error] {rel_path}:{lineno} 译文无法编码为 {out_encoding}: '
                  f'{e}  译文: {new_text!r}', file=sys.stderr)
            continue

    # 组装
    out_bytes = eol_bytes.join(lines_b)
    if trailing_eol:
        out_bytes += eol_bytes

    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(out_bytes)


def main():
    ap = argparse.ArgumentParser(description='AdvSystem 脚本注入')
    ap.add_argument('source_dir', help='源脚本目录 (原始日文)')
    ap.add_argument('trans_json', help='译文 JSON')
    ap.add_argument('output_dir', help='输出目录')
    ap.add_argument('--encoding', default='cp932',
                    help='输出文件编码 (默认 cp932; 中文汉化用 gbk)')
    args = ap.parse_args()

    if not os.path.isdir(args.source_dir):
        print(f'错误: 源目录不存在 {args.source_dir}', file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.trans_json):
        print(f'错误: JSON 不存在 {args.trans_json}', file=sys.stderr)
        sys.exit(1)

    trans_by_file = load_translations(args.trans_json)
    print(f'译文 JSON: {sum(len(v) for v in trans_by_file.values())} 条, '
          f'{len(trans_by_file)} 个文件')

    stats = {
        'injected': 0,
        'empty_kept': 0,
        'encode_fail': 0,
        'src_decode_fail': 0,
        'kind_mismatch': 0,
        'line_classify_mismatch': 0,
    }
    processed = 0
    copied = 0

    # 处理脚本文件
    matched_files = set(trans_by_file.keys())

    for abs_path, rel_path in iter_scripts(args.source_dir):
        out_path = os.path.join(args.output_dir, rel_path.replace('/', os.sep))
        if rel_path in trans_by_file:
            inject_file(abs_path, rel_path, trans_by_file[rel_path], out_path, stats,
                        args.encoding)
            processed += 1
        else:
            copy_file(abs_path, out_path)
            copied += 1

    # 其它文件 (manifest.json / 非脚本资源) 原样复制
    other_copied = 0
    for dirpath, _, filenames in os.walk(args.source_dir):
        for fn in filenames:
            if fn.upper().endswith(('.TXT', '.STX')):
                continue
            ap_ = os.path.join(dirpath, fn)
            rp_ = os.path.relpath(ap_, args.source_dir)
            out_path = os.path.join(args.output_dir, rp_)
            copy_file(ap_, out_path)
            other_copied += 1

    # 报告 JSON 中存在但源目录中没找到的文件
    scanned = set()
    for _, rp in iter_scripts(args.source_dir):
        scanned.add(rp)
    missing = matched_files - scanned
    if missing:
        print(f'\n[warn] JSON 中存在但源目录没有的文件 ({len(missing)}):', file=sys.stderr)
        for m in sorted(missing):
            print(f'  {m}', file=sys.stderr)

    print()
    print(f'处理脚本: {processed}, 原样复制脚本: {copied}, 其它文件复制: {other_copied}')
    print(f'成功注入: {stats["injected"]}')
    print(f'空翻译保留原文: {stats["empty_kept"]}')
    print(f'编码失败(译文): {stats["encode_fail"]}')
    print(f'源行解码失败: {stats["src_decode_fail"]}')
    print(f'种类不匹配: {stats["kind_mismatch"]}')
    print(f'分类不一致: {stats["line_classify_mismatch"]}')
    print(f'输出: {args.output_dir}')
    print(f'译文行编码: {args.encoding} (未翻译行保留源字节)')


if __name__ == '__main__':
    main()
