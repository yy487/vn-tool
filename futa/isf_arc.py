#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2MPX10 (ISF archive) 解包/封包工具
引擎: SM2 (ペンギンワークス系列, HIMITSU 等)

格式 (version 2, magic "SM2MPX10"):
  0x00  8B  magic "SM2MPX10"
  0x08  4B  entry_count (uint32 LE)
  0x0C  4B  data_start_offset (= 0x20 + count*0x14)
  0x10  4B  "Isf\0"  (subtype tag)
  0x14 12B  padding/reserved (00)
  0x20      index[count], 每条 0x14 字节:
              12B  name (CP932, null 结尾)
               4B  offset (相对文件开头)
               4B  size
  data_start: 紧密排列的各文件原始字节

无加密、无压缩。封包时按原顺序紧密重排即可。
"""
import os, sys, struct, argparse

MAGIC = b'SM2MPX10'
SUBTYPE = b'Isf\0'
HEADER_SIZE = 0x20
ENTRY_SIZE = 0x14

def unpack(arc_path, out_dir):
    with open(arc_path, 'rb') as f:
        data = f.read()
    if data[:8] != MAGIC:
        raise ValueError(f'不是 SM2MPX10 封包: magic={data[:8]!r}')
    count, data_start = struct.unpack_from('<II', data, 8)
    subtype = data[0x10:0x14]
    subtype_name = subtype.rstrip(b'\0').decode()
    print(f'[i] magic={MAGIC.decode()} subtype={subtype_name}')
    print(f'[i] 条目数 = {count}, 数据起始 = 0x{data_start:X}')
    expect = HEADER_SIZE + count * ENTRY_SIZE
    if expect != data_start:
        print(f'[!] 警告: 预期 data_start=0x{expect:X}, 实际=0x{data_start:X}')

    os.makedirs(out_dir, exist_ok=True)
    entries = []
    for i in range(count):
        base = HEADER_SIZE + i * ENTRY_SIZE
        raw = data[base:base+ENTRY_SIZE]
        name = raw[:12].split(b'\0', 1)[0].decode('cp932')
        offset, size = struct.unpack_from('<II', raw, 12)
        entries.append((name, offset, size))
        out_path = os.path.join(out_dir, name)
        with open(out_path, 'wb') as f:
            f.write(data[offset:offset+size])
        print(f'  [{i:03d}] {name:<14s} @0x{offset:08X} size=0x{size:08X}')

    # 保存原始顺序列表, 封包时按此顺序重建
    with open(os.path.join(out_dir, '_order.txt'), 'w', encoding='utf-8') as f:
        f.write(subtype.rstrip(b'\0').decode() + '\n')
        for name, _, _ in entries:
            f.write(name + '\n')
    print(f'[+] 解包完成: {count} 个文件 -> {out_dir}')

def pack(in_dir, arc_path):
    order_file = os.path.join(in_dir, '_order.txt')
    if not os.path.exists(order_file):
        raise FileNotFoundError(f'缺少 _order.txt ({order_file})')
    with open(order_file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]
    subtype_str = lines[0]
    names = lines[1:]
    count = len(names)
    # header 里 data_start 字段存 index 结束位置 (未对齐)
    # 但实际第一个文件从 0x10 对齐位置开始
    data_start_field = HEADER_SIZE + count * ENTRY_SIZE
    first_data = (data_start_field + 0xF) & ~0xF

    # 先读所有文件 (每个文件起始 0x10 对齐)
    files = []
    cur = first_data
    for name in names:
        p = os.path.join(in_dir, name)
        with open(p, 'rb') as f:
            body = f.read()
        files.append((name, cur, len(body), body))
        cur += len(body)
        # 0x10 对齐填充
        pad = (-cur) & 0xF
        cur += pad

    # 组装 header
    # 布局: magic(8) + count(4) + data_start(4) + "Isf\0"(4) + 0*8 + 0x20(4) = 0x20
    out = bytearray()
    out += MAGIC
    out += struct.pack("<II", count, data_start_field)
    subtype_bytes = subtype_str.encode('ascii').ljust(4, b'\0')
    out += subtype_bytes
    out += b'\0' * 8
    out += struct.pack('<I', HEADER_SIZE)  # header_size 字段 @0x1C
    assert len(out) == HEADER_SIZE

    for name, off, sz, _ in files:
        name_bytes = name.encode('cp932')
        if len(name_bytes) >= 12:
            raise ValueError(f'文件名过长 (>=12 字节): {name}')
        name_bytes = name_bytes.ljust(12, b'\0')
        out += name_bytes + struct.pack('<II', off, sz)
    # index 后补齐到 data_start
    while len(out) < first_data:
        out += b'\0'

    for i, (_, off, _, body) in enumerate(files):
        # pad 到此 offset
        while len(out) < off:
            out += b'\0'
        out += body
    # 文件末尾 0x10 对齐
    while len(out) & 0xF:
        out += b'\0'

    with open(arc_path, 'wb') as f:
        f.write(out)
    print(f'[+] 封包完成: {count} 个文件 -> {arc_path} ({len(out)} bytes)')

def main():
    ap = argparse.ArgumentParser(description='SM2MPX10 (ISF) 解包/封包工具')
    sub = ap.add_subparsers(dest='cmd', required=True)
    u = sub.add_parser('unpack', help='解包 ISF')
    u.add_argument('arc')
    u.add_argument('out_dir')
    p = sub.add_parser('pack', help='封包目录为 ISF')
    p.add_argument('in_dir')
    p.add_argument('arc')
    args = ap.parse_args()
    if args.cmd == 'unpack':
        unpack(args.arc, args.out_dir)
    else:
        pack(args.in_dir, args.arc)

if __name__ == '__main__':
    main()
