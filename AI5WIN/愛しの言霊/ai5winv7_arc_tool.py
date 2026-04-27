#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai5winv7_arc_tool.py — AI5WIN V7 (愛しの言霊 / シルキーズ 2001) ARC 封包工具

ARC 格式 (V7 独有, 与 V1-V6 全部不同):
  Header:
    u32  count                                  // 条目数
  Entry (28 字节):
    byte name[20]                              // 文件名, 每字节 ^ 0x03
    u32  size   ^ 0x53336560                   // 大小 (注意 size 在前, 反直觉!)
    u32  offset ^ 0x53336561                   // 文件起始偏移 (相对文件头)
  Data:
    连续存储, 首条 offset == 4 + count*28

关键特征:
  - 28 字节条目, 不同于 V1-V6 的 20/28/0x108 大小
  - **size 字段在 offset 之前**, 这是 V7 独特的反直觉顺序
  - 三把独立密钥 (name/size/offset) 均不相同
  - 解密后 size 必须是 <= 文件总长的合理值, 首条 offset 必须精确匹配

用法:
  ai5winv7_arc_tool.py list    <arc>
  ai5winv7_arc_tool.py unpack  <arc> <out_dir>
  ai5winv7_arc_tool.py pack    <in_dir> <arc>
  ai5winv7_arc_tool.py verify  <arc> <out_dir>    # round-trip: unpack 再 pack 后 MD5 比对
"""
import os, sys, struct, hashlib


# ---------------------------------------------------------------------------
# 密钥常量 (从 FUN_004XXXXX arc-loader 中静态验证)
# ---------------------------------------------------------------------------
NAME_XOR    = 0x03          # byte
SIZE_KEY    = 0x53336560    # u32
OFFSET_KEY  = 0x53336561    # u32
ENTRY_SIZE  = 28            # 20 (name) + 4 (size) + 4 (offset)
NAME_LEN    = 20


# ---------------------------------------------------------------------------
# 核心 I/O: entry 编解码
# ---------------------------------------------------------------------------
def decode_entry(raw):
    """解码 28 字节 entry -> (name_str, size, offset)"""
    assert len(raw) == ENTRY_SIZE
    name_bytes = bytes((b ^ NAME_XOR) for b in raw[:NAME_LEN])
    # 截断到首个 \0
    nul = name_bytes.find(b'\x00')
    if nul >= 0:
        name_bytes = name_bytes[:nul]
    name = name_bytes.decode('ascii', errors='replace')
    size_enc, off_enc = struct.unpack('<II', raw[NAME_LEN:NAME_LEN+8])
    size   = size_enc ^ SIZE_KEY
    offset = off_enc ^ OFFSET_KEY
    return name, size, offset


def encode_entry(name, size, offset):
    """编码 (name_str, size, offset) -> 28 字节 entry"""
    name_bytes = name.encode('ascii').ljust(NAME_LEN, b'\x00')[:NAME_LEN]
    enc_name = bytes((b ^ NAME_XOR) for b in name_bytes)
    size_enc = size   ^ SIZE_KEY
    off_enc  = offset ^ OFFSET_KEY
    return enc_name + struct.pack('<II', size_enc, off_enc)


def read_index(data):
    """从完整的 ARC 字节流读索引, 返回 [(name, size, offset), ...]"""
    if len(data) < 4:
        raise ValueError('ARC too small')
    count = struct.unpack('<I', data[:4])[0]
    if count > 100000:
        raise ValueError(f'unreasonable count {count}')
    header_end = 4 + count * ENTRY_SIZE
    if header_end > len(data):
        raise ValueError(f'header overflows file ({header_end} > {len(data)})')
    entries = []
    for i in range(count):
        off = 4 + i * ENTRY_SIZE
        entries.append(decode_entry(data[off : off + ENTRY_SIZE]))
    return entries


def sanity_check(entries, file_size):
    """交叉验证: 所有 size+offset 都在 file 内, 且首条 offset 恰好等于 header_end"""
    if not entries:
        return
    header_end = 4 + len(entries) * ENTRY_SIZE
    first_off = entries[0][2]
    if first_off != header_end:
        raise ValueError(
            f'first offset {first_off:#x} != header_end {header_end:#x} '
            '(密钥错误或格式不符)'
        )
    for name, size, offset in entries:
        if offset + size > file_size:
            raise ValueError(f'entry {name!r}: {offset:#x}+{size:#x} > {file_size:#x}')


# ---------------------------------------------------------------------------
# 高层操作
# ---------------------------------------------------------------------------
def cmd_list(arc_path):
    with open(arc_path, 'rb') as f:
        data = f.read()
    entries = read_index(data)
    sanity_check(entries, len(data))
    print(f'{arc_path}: {len(entries)} entries')
    total = 0
    for name, size, offset in entries:
        print(f'  {name:24} off={offset:#010x} size={size:#10x}')
        total += size
    print(f'  total data: {total:#x} ({total} bytes)')


def cmd_unpack(arc_path, out_dir):
    with open(arc_path, 'rb') as f:
        data = f.read()
    entries = read_index(data)
    sanity_check(entries, len(data))
    os.makedirs(out_dir, exist_ok=True)
    # 保留原顺序 (用于后续 pack 字节级重建)
    order_path = os.path.join(out_dir, '_order.txt')
    with open(order_path, 'w', encoding='utf-8') as of:
        for name, size, offset in entries:
            blob = data[offset : offset + size]
            out_path = os.path.join(out_dir, name)
            with open(out_path, 'wb') as bf:
                bf.write(blob)
            of.write(name + '\n')
    print(f'unpacked {len(entries)} files → {out_dir}/')


def cmd_pack(in_dir, arc_path):
    # 读取 _order.txt 恢复原顺序, 保证 round-trip 字节级一致
    order_path = os.path.join(in_dir, '_order.txt')
    if os.path.exists(order_path):
        with open(order_path, 'r', encoding='utf-8') as f:
            names = [line.strip() for line in f if line.strip()]
    else:
        names = sorted(f for f in os.listdir(in_dir)
                       if os.path.isfile(os.path.join(in_dir, f))
                       and not f.startswith('_'))
    count = len(names)
    header_end = 4 + count * ENTRY_SIZE

    # 一次读所有文件, 分配偏移
    blobs = []
    offset = header_end
    entries = []
    for name in names:
        p = os.path.join(in_dir, name)
        with open(p, 'rb') as f:
            blob = f.read()
        entries.append((name, len(blob), offset))
        blobs.append(blob)
        offset += len(blob)

    with open(arc_path, 'wb') as f:
        f.write(struct.pack('<I', count))
        for name, size, off in entries:
            f.write(encode_entry(name, size, off))
        for blob in blobs:
            f.write(blob)
    print(f'packed {count} files → {arc_path} ({offset} bytes)')


def cmd_verify(arc_path, tmp_dir):
    """round-trip: unpack -> pack -> MD5 比对"""
    with open(arc_path, 'rb') as f:
        orig = f.read()
    orig_md5 = hashlib.md5(orig).hexdigest()

    cmd_unpack(arc_path, tmp_dir)
    rebuilt_path = arc_path + '.rebuilt'
    cmd_pack(tmp_dir, rebuilt_path)
    with open(rebuilt_path, 'rb') as f:
        rebuilt = f.read()
    new_md5 = hashlib.md5(rebuilt).hexdigest()

    print()
    print(f'原 ARC  MD5: {orig_md5}')
    print(f'重建 MD5   : {new_md5}')
    if orig_md5 == new_md5:
        print('✅ round-trip 字节级一致')
    else:
        print('❌ MD5 不一致!')
        # 找首差
        for i, (a, b) in enumerate(zip(orig, rebuilt)):
            if a != b:
                print(f'  首个差异 @ 0x{i:x}: {a:02x} vs {b:02x}')
                break
        if len(orig) != len(rebuilt):
            print(f'  长度不同: {len(orig)} vs {len(rebuilt)}')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _usage():
    print(__doc__)


def main():
    if len(sys.argv) < 2:
        _usage(); return
    cmd = sys.argv[1]
    try:
        if cmd == 'list' and len(sys.argv) == 3:
            cmd_list(sys.argv[2])
        elif cmd == 'unpack' and len(sys.argv) == 4:
            cmd_unpack(sys.argv[2], sys.argv[3])
        elif cmd == 'pack' and len(sys.argv) == 4:
            cmd_pack(sys.argv[2], sys.argv[3])
        elif cmd == 'verify' and len(sys.argv) == 4:
            cmd_verify(sys.argv[2], sys.argv[3])
        else:
            _usage()
    except Exception as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
