#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dat_tool.py  —  Studio e.go! 引擎 DAT 归档 (DAT/EGO/0, OldDat 变体) 解包/封包工具

格式:
    u32 index_size              ; 不含自身, data_offset = 4 + index_size
    entries[]:                  ; 每条变长, 紧密排列至 data_offset
        u32 entry_len           ; 包含自身, = 12 + namelen (name 含尾 \0)
        u32 file_offset         ; 相对文件起点
        u32 file_size
        bytes name              ; CP932, 以 \0 结尾并填充到 namelen
    data:                       ; 文件内容连续堆放

已知引擎: Studio e.go! / TwinWay (如 tw.exe, 『Yuki☆Uta』 等)

用法:
    python dat_tool.py list    game00.dat
    python dat_tool.py unpack  game00.dat  out_dir/
    python dat_tool.py pack    out_dir/    game00_new.dat
    python dat_tool.py verify  game00.dat  game00_new.dat
"""
import os
import sys
import struct
import argparse
import hashlib


# ---------- 解包 ----------

def parse_index(data: bytes):
    """解析索引, 返回 [(name, offset, size), ...] 和 data_offset。"""
    if len(data) < 4:
        raise ValueError("文件太短, 不像 DAT 归档")
    index_size = struct.unpack_from('<I', data, 0)[0]
    data_offset = 4 + index_size
    if data_offset > len(data):
        raise ValueError(f"index_size={index_size:#x} 超出文件范围")

    entries = []
    p = 4
    while p < data_offset:
        if p + 12 > data_offset:
            raise ValueError(f"@{p:#x}: entry 头被截断")
        entry_len = struct.unpack_from('<I', data, p)[0]
        if entry_len <= 12 or p + entry_len > data_offset:
            raise ValueError(f"@{p:#x}: 不合法 entry_len={entry_len}")
        foff = struct.unpack_from('<I', data, p + 4)[0]
        fsz  = struct.unpack_from('<I', data, p + 8)[0]
        name_raw = data[p + 12 : p + entry_len]
        # name 以 \0 结尾并填充, 去掉所有尾部 \0
        name = name_raw.rstrip(b'\x00').decode('cp932')
        if not name:
            raise ValueError(f"@{p:#x}: 空文件名")
        if foff < data_offset or foff + fsz > len(data):
            raise ValueError(f"@{p:#x} {name}: offset/size 越界 "
                             f"(foff={foff:#x}, fsz={fsz:#x})")
        entries.append((name, foff, fsz))
        p += entry_len

    if p != data_offset:
        raise ValueError(f"索引结束位置 {p:#x} 与 data_offset {data_offset:#x} 不一致")
    return entries, data_offset


def cmd_list(args):
    data = open(args.archive, 'rb').read()
    entries, data_off = parse_index(data)
    print(f"Archive : {args.archive}")
    print(f"Size    : {len(data):,} bytes")
    print(f"Entries : {len(entries)}")
    print(f"DataOff : 0x{data_off:x}")
    print()
    print(f"{'Offset':>10}  {'Size':>10}  Name")
    print("-" * 60)
    for name, off, sz in entries:
        print(f"0x{off:08x}  {sz:>10}  {name}")


def cmd_unpack(args):
    data = open(args.archive, 'rb').read()
    entries, _ = parse_index(data)
    os.makedirs(args.outdir, exist_ok=True)

    # 保存原始顺序以便 pack 时复原 (引擎靠索引表查表, 顺序理论上无所谓,
    # 但保序可以让 round-trip 产出字节级相同的文件)
    order_path = os.path.join(args.outdir, '_order.txt')
    with open(order_path, 'w', encoding='utf-8') as f:
        for name, _, _ in entries:
            f.write(name + '\n')

    for i, (name, off, sz) in enumerate(entries):
        # 将 Windows 反斜杠规整为系统路径
        safe_name = name.replace('\\', os.sep)
        out_path = os.path.join(args.outdir, safe_name)
        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(data[off:off + sz])
        if (i + 1) % 50 == 0 or i == len(entries) - 1:
            print(f"  [{i+1}/{len(entries)}] {name}")
    print(f"✓ 解包完成: {len(entries)} 个文件 → {args.outdir}")


# ---------- 封包 ----------

def cmd_pack(args):
    indir = args.indir
    order_path = os.path.join(indir, '_order.txt')
    if os.path.exists(order_path):
        # 按原始顺序打包
        with open(order_path, encoding='utf-8') as f:
            names = [ln.rstrip('\n\r') for ln in f if ln.strip()]
        print(f"  使用 _order.txt ({len(names)} 条)")
    else:
        # 没有 order 文件就递归扫, 按排序打包
        names = []
        for root, _, files in os.walk(indir):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, indir).replace(os.sep, '\\')
                names.append(rel)
        names.sort()
        print(f"  未找到 _order.txt, 递归扫描得到 {len(names)} 条")

    # 读取每个文件并准备条目
    entry_infos = []  # (name_bytes_with_null, file_bytes)
    for name in names:
        safe_name = name.replace('\\', os.sep)
        full = os.path.join(indir, safe_name)
        if not os.path.isfile(full):
            raise FileNotFoundError(f"缺少文件: {full}")
        try:
            name_enc = name.encode('cp932')
        except UnicodeEncodeError as e:
            raise ValueError(f"文件名含 CP932 无法表示的字符: {name!r}") from e
        name_field = name_enc + b'\x00'  # 至少 1 字节结尾
        # 原文件中 name 字段是否有额外 padding? 从样本看没有,
        # entry_len 恰好 = 12 + len(name) + 1, 这里保持最小
        data_bytes = open(full, 'rb').read()
        entry_infos.append((name_field, data_bytes))

    # 第一轮: 算 index_size (偏移未知, 先写占位)
    index_size = 0
    for name_field, _ in entry_infos:
        entry_len = 12 + len(name_field)
        index_size += entry_len
    data_offset = 4 + index_size

    # 第二轮: 计算每个文件 offset
    offsets = []
    cur = data_offset
    for _, d in entry_infos:
        offsets.append(cur)
        cur += len(d)
    total_size = cur

    # 写入
    out = bytearray(total_size)
    struct.pack_into('<I', out, 0, index_size)

    p = 4
    for (name_field, d), off in zip(entry_infos, offsets):
        entry_len = 12 + len(name_field)
        struct.pack_into('<III', out, p, entry_len, off, len(d))
        out[p + 12 : p + entry_len] = name_field
        p += entry_len
    assert p == data_offset, f"索引写入长度不一致 {p} vs {data_offset}"

    # 文件数据
    for (name_field, d), off in zip(entry_infos, offsets):
        out[off:off + len(d)] = d

    with open(args.archive, 'wb') as f:
        f.write(out)
    print(f"✓ 封包完成: {len(entry_infos)} 个文件, {total_size:,} bytes → {args.archive}")


# ---------- 校验 ----------

def cmd_verify(args):
    a = open(args.archive1, 'rb').read()
    b = open(args.archive2, 'rb').read()
    ea, _ = parse_index(a)
    eb, _ = parse_index(b)

    print(f"{args.archive1}: {len(a):,} bytes, {len(ea)} entries, "
          f"md5={hashlib.md5(a).hexdigest()}")
    print(f"{args.archive2}: {len(b):,} bytes, {len(eb)} entries, "
          f"md5={hashlib.md5(b).hexdigest()}")

    if a == b:
        print("✓ 完全字节级一致 (bit-perfect round-trip)")
        return

    if len(ea) != len(eb):
        print(f"✗ entry 数量不同: {len(ea)} vs {len(eb)}")
        return

    # 按名字对比内容
    map_a = {n: (o, s) for n, o, s in ea}
    map_b = {n: (o, s) for n, o, s in eb}
    only_a = set(map_a) - set(map_b)
    only_b = set(map_b) - set(map_a)
    if only_a:
        print(f"✗ 仅在 {args.archive1}: {len(only_a)} 条")
        for n in list(only_a)[:5]:
            print(f"    {n}")
    if only_b:
        print(f"✗ 仅在 {args.archive2}: {len(only_b)} 条")
        for n in list(only_b)[:5]:
            print(f"    {n}")

    mismatches = 0
    for name in map_a:
        if name not in map_b:
            continue
        oa, sa = map_a[name]
        ob, sb = map_b[name]
        if sa != sb or a[oa:oa + sa] != b[ob:ob + sb]:
            mismatches += 1
            if mismatches <= 5:
                print(f"✗ 内容不同: {name} ({sa} vs {sb})")

    if mismatches == 0 and not only_a and not only_b:
        print("✓ 内容一致 (仅 entry 顺序/布局不同)")
    else:
        print(f"共 {mismatches} 个文件内容不一致")


# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser(
        description="Studio e.go! DAT 归档解包/封包工具 (DAT/EGO/0 变体)")
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('list', help='列出归档中的文件')
    p.add_argument('archive')
    p.set_defaults(func=cmd_list)

    p = sub.add_parser('unpack', help='解包归档')
    p.add_argument('archive')
    p.add_argument('outdir')
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser('pack', help='封包目录为归档')
    p.add_argument('indir')
    p.add_argument('archive')
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser('verify', help='对比两个归档 (用于 round-trip 校验)')
    p.add_argument('archive1')
    p.add_argument('archive2')
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
