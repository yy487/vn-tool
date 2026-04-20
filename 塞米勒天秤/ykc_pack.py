#!/usr/bin/env python3
"""
ykc_pack.py - Yuka Engine YKC 封包/解包工具

用法:
  python ykc_pack.py unpack  input.ykc  output_dir/     # 解包
  python ykc_pack.py pack    input_dir/  output.ykc      # 封包
  python ykc_pack.py list    input.ykc                   # 列出文件

封包时保持目录结构: input_dir/yks/01.yks → 封包内路径 yks\\01.yks
"""

import struct
import sys
import os


def ykc_unpack(ykc_path, out_dir):
    with open(ykc_path, 'rb') as f:
        data = f.read()

    magic = data[:4]
    if magic != b'YKC0':
        raise ValueError(f"不是YKC文件: {magic}")

    version = data[4:8]
    index_offset = struct.unpack_from('<I', data, 0x10)[0]
    index_length = struct.unpack_from('<I', data, 0x14)[0]
    count = index_length // 0x14

    print(f"版本: {version}")
    print(f"文件数: {count}")

    encoding = 'utf-8' if version == b'02\x00\x00' else 'cp932'

    for i in range(count):
        base = index_offset + i * 0x14
        name_off  = struct.unpack_from('<I', data, base)[0]
        name_len  = struct.unpack_from('<I', data, base + 4)[0]
        data_off  = struct.unpack_from('<I', data, base + 8)[0]
        data_size = struct.unpack_from('<I', data, base + 0xC)[0]

        name = data[name_off:name_off + name_len].rstrip(b'\x00').decode(encoding, errors='replace')
        # 统一路径分隔符
        name = name.replace('\\', os.sep).replace('/', os.sep)

        out_path = os.path.join(out_dir, name)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        with open(out_path, 'wb') as f:
            f.write(data[data_off:data_off + data_size])

    print(f"解包完成: {count} 文件 → {out_dir}")


def ykc_pack(in_dir, ykc_path):
    # 收集所有文件，保持相对路径（用 \ 分隔，YKC惯例）
    files = []
    for root, dirs, fnames in os.walk(in_dir):
        dirs.sort()
        for fn in sorted(fnames):
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, in_dir)
            # YKC内部用 \ 分隔
            rel_ykc = rel.replace(os.sep, '\\')
            files.append((full, rel_ykc))

    if not files:
        print(f"错误: {in_dir} 下没有文件")
        return

    print(f"封包: {len(files)} 文件")

    # 阶段1: 写 header 占位 + 文件数据
    out = bytearray()
    out += b'\x00' * 0x18  # header 占位

    file_entries = []  # (name_bytes, data_offset, data_size)
    for full_path, rel_name in files:
        with open(full_path, 'rb') as f:
            fdata = f.read()

        data_offset = len(out)
        data_size = len(fdata)
        out += fdata

        name_bytes = rel_name.encode('cp932') + b'\x00'
        file_entries.append((name_bytes, data_offset, data_size))

    # 阶段2: 写文件名
    name_offsets = []
    for name_bytes, _, _ in file_entries:
        name_offsets.append(len(out))
        out += name_bytes

    # 阶段3: 写索引表
    index_offset = len(out)
    for i, (name_bytes, data_offset, data_size) in enumerate(file_entries):
        out += struct.pack('<5I',
            name_offsets[i],
            len(name_bytes),
            data_offset,
            data_size,
            0
        )
    index_length = len(out) - index_offset

    # 阶段4: 回填 header
    header = b'YKC001\x00\x00'
    header += struct.pack('<I', 0x18)
    header += struct.pack('<I', 0)       # reserved
    header += struct.pack('<I', index_offset)
    header += struct.pack('<I', index_length)
    out[:0x18] = header

    with open(ykc_path, 'wb') as f:
        f.write(out)

    print(f"封包完成: {ykc_path} ({len(out)} bytes, {len(files)} 文件)")


def ykc_list(ykc_path):
    with open(ykc_path, 'rb') as f:
        data = f.read()

    magic = data[:4]
    if magic != b'YKC0':
        raise ValueError(f"不是YKC文件: {magic}")

    version = data[4:8]
    index_offset = struct.unpack_from('<I', data, 0x10)[0]
    index_length = struct.unpack_from('<I', data, 0x14)[0]
    count = index_length // 0x14

    encoding = 'utf-8' if version == b'02\x00\x00' else 'cp932'

    total_size = 0
    for i in range(count):
        base = index_offset + i * 0x14
        name_off  = struct.unpack_from('<I', data, base)[0]
        name_len  = struct.unpack_from('<I', data, base + 4)[0]
        data_off  = struct.unpack_from('<I', data, base + 8)[0]
        data_size = struct.unpack_from('<I', data, base + 0xC)[0]

        name = data[name_off:name_off + name_len].rstrip(b'\x00').decode(encoding, errors='replace')
        total_size += data_size
        print(f"  {data_size:10d}  {name}")

    print(f"\n{count} 文件, {total_size} bytes total")


def usage():
    print("ykc_pack.py - Yuka Engine YKC 封包/解包工具")
    print()
    print("  python ykc_pack.py unpack  input.ykc  output_dir/")
    print("  python ykc_pack.py pack    input_dir/  output.ykc")
    print("  python ykc_pack.py list    input.ykc")
    sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage()

    cmd = sys.argv[1].lower()

    if cmd == 'unpack' and len(sys.argv) == 4:
        ykc_unpack(sys.argv[2], sys.argv[3])
    elif cmd == 'pack' and len(sys.argv) == 4:
        ykc_pack(sys.argv[2], sys.argv[3])
    elif cmd == 'list' and len(sys.argv) == 3:
        ykc_list(sys.argv[2])
    else:
        usage()
