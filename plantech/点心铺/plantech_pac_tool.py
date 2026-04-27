#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plantech_pac_tool.py — PLANTECH 引擎 PAC 图像格式解包/封包

格式 (来自 GARbro/morkt 源码):
  PAC = 8 字节前缀 + 标准 BMP
  +0..4  : u32 = 0          (固定 0, ImageFormat.Signature 检查)
  +4..8  : u32 = bmp_size   (与 BMP 头里 bfSize 字段相同)
  +8..   : 标准 BMP 文件 (BM magic + DIB)

也就是说: 砍掉前 8 字节 = 一个能直接打开的 BMP.
反过来: BMP 前面拼 [00 00 00 00] [bmp_size_le32] = PAC.

支持的位深 (引擎): 8/16/24/32 bpp.

用法:
  decode:  python plantech_pac_tool.py decode <input.pac> [-o out.png]
  encode:  python plantech_pac_tool.py encode <input.png> [-o out.pac]
  batch:   python plantech_pac_tool.py batch <input_dir> -o <out_dir>
                                              [--mode decode|encode]
                                              [--ext .png]
"""

import argparse
import os
import struct
import sys
from io import BytesIO

try:
    from PIL import Image
except ImportError:
    print('需要 Pillow: pip install pillow')
    sys.exit(1)


# ---------- 单文件操作 ----------

def pac_to_bmp_bytes(pac_data: bytes) -> bytes:
    """剥离 PAC 8 字节前缀, 验证后返回内部 BMP 字节流."""
    if len(pac_data) < 14:
        raise ValueError('文件过短, 不是合法 PAC')
    sig = struct.unpack_from('<I', pac_data, 0)[0]
    if sig != 0:
        raise ValueError(f'PAC 前 4 字节应为 0, 实为 0x{sig:08x}')
    pac_size = struct.unpack_from('<I', pac_data, 4)[0]
    if pac_data[8:10] != b'BM':
        raise ValueError(f'偏移 8 处缺少 BM 标记, 实为 {pac_data[8:10]}')
    bmp_size = struct.unpack_from('<I', pac_data, 10)[0]
    if pac_size != bmp_size:
        raise ValueError(
            f'PAC size 字段 (0x{pac_size:x}) 与 BMP bfSize (0x{bmp_size:x}) 不一致'
        )
    return pac_data[8:]


def decode_one(pac_path: str, out_path: str) -> None:
    pac = open(pac_path, 'rb').read()
    bmp = pac_to_bmp_bytes(pac)
    img = Image.open(BytesIO(bmp))
    img.load()
    # PLANTECH 引擎实际按 top-down 渲染, 但 BMP 头声明 bottom-up,
    # 所以 Pillow 自动翻正后图像反而是倒的, 需要再垂直翻一次.
    img = img.transpose(Image.FLIP_TOP_BOTTOM)
    img.save(out_path)
    print(f'  {os.path.basename(pac_path)}  ->  {os.path.basename(out_path)}  '
          f'[{img.mode} {img.size[0]}x{img.size[1]}]')


def encode_one(img_path: str, out_path: str) -> None:
    """把任意 PIL 可读图片转 PAC.

    位深规则:
      原图 RGB/RGBA -> 24bpp BMP
      原图 L (灰度) -> 8bpp BMP (GARbro 支持)
    其他模式会先转 RGB.
    """
    img = Image.open(img_path)
    img.load()
    if img.mode == 'L':
        target_mode = 'L'
    elif img.mode in ('RGB', 'RGBA', 'P'):
        target_mode = 'RGB'
        img = img.convert('RGB')
    else:
        target_mode = 'RGB'
        img = img.convert('RGB')

    # 引擎按 top-down 显示, 而 BMP 头会声明 bottom-up, 所以我们要先垂直翻
    # 一次 (与 decode 对称), 让最终写出的 BMP 像素方向匹配引擎期望.
    img = img.transpose(Image.FLIP_TOP_BOTTOM)

    buf = BytesIO()
    img.save(buf, format='BMP')
    bmp = buf.getvalue()

    # BMP 头 +2 处是 bfSize
    bmp_size = struct.unpack_from('<I', bmp, 2)[0]
    if bmp_size != len(bmp):
        # Pillow 写 BMP 有时 bfSize 字段就是文件大小, 但保险起见以实际为准
        bmp_size = len(bmp)
        bmp = bmp[:2] + struct.pack('<I', bmp_size) + bmp[6:]

    # PAC 前缀: u32 0 + u32 bmp_size
    pac = struct.pack('<II', 0, bmp_size) + bmp
    with open(out_path, 'wb') as f:
        f.write(pac)
    print(f'  {os.path.basename(img_path)}  ->  {os.path.basename(out_path)}  '
          f'[{target_mode} {img.size[0]}x{img.size[1]}, {len(pac)} bytes]')


# ---------- 批量 ----------

def batch(in_dir: str, out_dir: str, mode: str, out_ext: str) -> None:
    if mode == 'decode':
        in_ext = '.pac'
        op = decode_one
    elif mode == 'encode':
        in_ext = out_ext.lower()  # 反过来: 输入是图片
        # encode 模式下 out_ext 是输入扩展名, 输出固定 .pac
        op = encode_one
    else:
        raise ValueError(mode)

    os.makedirs(out_dir, exist_ok=True)
    files = sorted(
        f for f in os.listdir(in_dir)
        if f.lower().endswith(in_ext if mode == 'decode' else out_ext.lower())
    )
    if not files:
        print(f'[!] 目录 {in_dir} 内未找到 {in_ext if mode=="decode" else out_ext} 文件')
        return

    print(f'[INFO] {mode} {len(files)} 个文件')
    ok = 0
    err = 0
    for name in files:
        src = os.path.join(in_dir, name)
        if mode == 'decode':
            dst = os.path.join(out_dir, os.path.splitext(name)[0] + out_ext)
        else:
            dst = os.path.join(out_dir, os.path.splitext(name)[0] + '.pac')
        try:
            op(src, dst)
            ok += 1
        except Exception as e:
            print(f'  [ERR] {name}: {e}')
            err += 1
    print(f'[OK] 成功 {ok}, 失败 {err}')


# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser(description='PLANTECH PAC 图像工具')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_d = sub.add_parser('decode', help='单文件: PAC -> PNG')
    p_d.add_argument('input')
    p_d.add_argument('-o', '--output', help='输出 PNG (默认同名 .png)')

    p_e = sub.add_parser('encode', help='单文件: PNG -> PAC')
    p_e.add_argument('input')
    p_e.add_argument('-o', '--output', help='输出 PAC (默认同名 .pac)')

    p_b = sub.add_parser('batch', help='批量目录处理')
    p_b.add_argument('input_dir')
    p_b.add_argument('-o', '--output', required=True, help='输出目录')
    p_b.add_argument('--mode', choices=['decode', 'encode'], default='decode',
                     help='decode: PAC->PNG (默认); encode: 图片->PAC')
    p_b.add_argument('--ext', default='.png',
                     help='decode 时输出图片格式扩展名 (.png/.bmp/...);'
                          ' encode 时输入图片扩展名 (默认 .png)')

    args = ap.parse_args()

    if args.cmd == 'decode':
        out = args.output or (os.path.splitext(args.input)[0] + '.png')
        decode_one(args.input, out)
    elif args.cmd == 'encode':
        out = args.output or (os.path.splitext(args.input)[0] + '.pac')
        encode_one(args.input, out)
    elif args.cmd == 'batch':
        batch(args.input_dir, args.output, args.mode, args.ext)


if __name__ == '__main__':
    main()
