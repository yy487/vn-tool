#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bmp2png.py —— BMP 批量/单文件转 PNG

用法:
    python bmp2png.py <input> [output] [--recursive] [--overwrite] [--delete-src]

参数:
    input       单个 .bmp 文件 或 目录
    output      输出路径 (文件→文件, 目录→目录; 省略则与输入同位置, 仅改后缀)
    --recursive 递归子目录 (仅对目录 input 有效)
    --overwrite 目标 PNG 已存在时覆盖 (默认跳过)
    --delete-src 转换成功后删除源 BMP (慎用)

依赖: Pillow (pip install pillow)

示例:
    # 单文件
    python bmp2png.py EV016A.BMP                 # -> EV016A.png
    python bmp2png.py EV016A.BMP out.png

    # 目录 (非递归)
    python bmp2png.py ac1_out/ png_out/

    # 目录 (递归, 保持子目录结构)
    python bmp2png.py ac1_out/ png_out/ --recursive
"""

import os
import sys
import argparse

try:
    from PIL import Image
except ImportError:
    print('错误: 需要 Pillow, 请先安装: pip install pillow', file=sys.stderr)
    sys.exit(1)


def convert_one(src, dst, overwrite=False, delete_src=False):
    """
    转换单个文件, 返回 'ok' | 'skip' | 'fail'
    """
    if os.path.exists(dst) and not overwrite:
        print(f'  [skip] {dst} 已存在 (用 --overwrite 覆盖)')
        return 'skip'
    try:
        with Image.open(src) as im:
            # BMP 可能是调色板模式 (P), 转 RGB/RGBA 后存 PNG
            if im.mode == 'P':
                im = im.convert('RGBA' if 'transparency' in im.info else 'RGB')
            os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
            im.save(dst, 'PNG', optimize=True)
        print(f'  [ok]   {src} -> {dst}  ({im.size[0]}x{im.size[1]} {im.mode})')
        if delete_src:
            os.remove(src)
        return 'ok'
    except Exception as e:
        print(f'  [fail] {src}: {e}', file=sys.stderr)
        return 'fail'


def is_bmp(path):
    return path.lower().endswith('.bmp')


def main():
    ap = argparse.ArgumentParser(description='BMP 转 PNG')
    ap.add_argument('input', help='源 .bmp 文件或目录')
    ap.add_argument('output', nargs='?', default=None,
                    help='目标路径 (文件/目录, 省略则就地改后缀)')
    ap.add_argument('--recursive', '-r', action='store_true',
                    help='递归遍历子目录')
    ap.add_argument('--overwrite', '-f', action='store_true',
                    help='覆盖已存在的目标 PNG')
    ap.add_argument('--delete-src', action='store_true',
                    help='转换成功后删除源 BMP')
    args = ap.parse_args()

    src = os.path.abspath(args.input)

    if not os.path.exists(src):
        print(f'错误: {src} 不存在', file=sys.stderr)
        sys.exit(1)

    # 文件模式
    if os.path.isfile(src):
        if not is_bmp(src):
            print(f'错误: {src} 不是 .bmp 文件', file=sys.stderr)
            sys.exit(1)
        if args.output:
            dst = os.path.abspath(args.output)
            # 如果 output 指向目录
            if os.path.isdir(dst) or args.output.endswith(os.sep) or args.output.endswith('/'):
                dst = os.path.join(dst, os.path.splitext(os.path.basename(src))[0] + '.png')
        else:
            dst = os.path.splitext(src)[0] + '.png'
        convert_one(src, dst, args.overwrite, args.delete_src)
        return

    # 目录模式
    in_dir = src
    out_dir = os.path.abspath(args.output) if args.output else in_dir

    stats = {'ok': 0, 'skip': 0, 'fail': 0}
    if args.recursive:
        walker = os.walk(in_dir)
    else:
        walker = [(in_dir, [], os.listdir(in_dir))]

    for dirpath, _, filenames in walker:
        for fn in sorted(filenames):
            if not is_bmp(fn):
                continue
            src_path = os.path.join(dirpath, fn)
            rel = os.path.relpath(src_path, in_dir)
            rel_png = os.path.splitext(rel)[0] + '.png'
            dst_path = os.path.join(out_dir, rel_png)
            r = convert_one(src_path, dst_path, args.overwrite, args.delete_src)
            stats[r] += 1

    print()
    print(f'完成: 成功 {stats["ok"]}, 跳过 {stats["skip"]}, 失败 {stats["fail"]}')


if __name__ == '__main__':
    main()
