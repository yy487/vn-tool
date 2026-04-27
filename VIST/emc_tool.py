#!/usr/bin/env python3
"""
EMC (EMSAC-Binary Archive-2) 解包/封包工具
适用引擎: EntisGLS / VIST (EScriptV2)
格式标识: 文件头 'VIST' + 'EMSAC-Binary Archive-2'
文件扩展名: .emc

用法:
  解包: python emc_tool.py unpack <input.emc> [output_dir]
  封包: python emc_tool.py repack <input_dir> <output.emc> [ref.emc]
  列表: python emc_tool.py list <input.emc>

格式说明:
  EMC文件结构:
    [0x00-0x3F] 文件头 (64字节)
      +0x00: 'VIST' (4字节 magic)
      +0x04: flags/version (12字节)
      +0x10: 'EMSAC-Binary Archive-2' (32字节, null填充)
      +0x30: padding (16字节)
    [0x40-0x4F] DirEntry段头
      +0x00: 'DirEntry' (8字节 tag)
      +0x08: section_size (u64 LE)
    [0x50+] DirEntry段数据
      +0x00: entry_count (u32)
      +0x04: 每条目固定0x24字节 + 变长路径/名称
        固定部分:
          +0x00: file_size (u64) — 嵌入文件大小(含VIST子头)
          +0x08: reserved (u64, 通常为0)
          +0x10: data_offset (u64) — 相对于段数据起始(0x50)的偏移
          +0x18: timestamp (u64, FILETIME格式)
          +0x20: path_string_size (u32)
        变长部分:
          path_string (path_string_size字节, null结尾)
          name_string_size (u32)
          name_string (name_string_size字节, null结尾)
    [段数据结束后] 文件数据区
      每个文件前有16字节前缀:
        +0x00: sequence_index (u64)
        +0x08: file_size (u64)
      然后是实际文件数据(以'VIST'开头的子文件)
"""

import struct
import sys
import os
from pathlib import Path


EMC_HEADER_SIZE = 0x40
SECTION_TAG_SIZE = 8
SECTION_SIZE_FIELD = 8
SECTION_HEADER_SIZE = SECTION_TAG_SIZE + SECTION_SIZE_FIELD  # 16
DIR_DATA_BASE = EMC_HEADER_SIZE + SECTION_HEADER_SIZE  # 0x50
ENTRY_FIXED_SIZE = 0x24  # 36 bytes
FILE_PREFIX_SIZE = 16


class EmcEntry:
    def __init__(self):
        self.file_size = 0
        self.reserved = 0
        self.data_offset = 0  # relative to DIR_DATA_BASE (0x50)
        self.timestamp = 0
        self.path = ""
        self.name = ""


def read_emc(filepath):
    """读取EMC文件，返回(header_bytes, entries, file_data_dict)"""
    with open(filepath, 'rb') as f:
        data = f.read()

    # 验证文件头
    if data[0:4] != b'VIST':
        raise ValueError(f"不是有效的EMC文件: magic = {data[0:4]}")

    format_str = data[0x10:0x30].rstrip(b'\x00').decode('ascii')
    if 'EMSAC-Binary Archive' not in format_str:
        raise ValueError(f"未知格式: {format_str}")

    # 读取DirEntry段
    section_tag = data[0x40:0x48].rstrip(b'\x00').decode('ascii')
    if section_tag != 'DirEntry':
        raise ValueError(f"期望DirEntry段，实际: {section_tag}")

    section_size = struct.unpack_from('<Q', data, 0x48)[0]
    entry_count = struct.unpack_from('<I', data, DIR_DATA_BASE)[0]

    # 解析条目
    entries = []
    pos = DIR_DATA_BASE + 4  # skip entry_count

    for i in range(entry_count):
        entry = EmcEntry()

        # 读取固定0x24字节
        entry.file_size = struct.unpack_from('<Q', data, pos)[0]
        entry.reserved = struct.unpack_from('<Q', data, pos + 8)[0]
        entry.data_offset = struct.unpack_from('<Q', data, pos + 0x10)[0]
        entry.timestamp = struct.unpack_from('<Q', data, pos + 0x18)[0]
        path_size = struct.unpack_from('<I', data, pos + 0x20)[0]
        pos += ENTRY_FIXED_SIZE

        # 读取路径
        entry.path = data[pos:pos + path_size].rstrip(b'\x00').decode('ascii', errors='replace')
        pos += path_size

        # 读取名称
        name_size = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        entry.name = data[pos:pos + name_size].rstrip(b'\x00').decode('ascii', errors='replace')
        pos += name_size

        entries.append(entry)

    # 保存原始头部(文件头 + DirEntry段头 + 段数据)
    header_end = DIR_DATA_BASE + section_size
    header_bytes = data[:EMC_HEADER_SIZE]  # 只保存文件头

    return data, entries


def cmd_list(filepath):
    """列出EMC内的所有文件"""
    data, entries = read_emc(filepath)

    print(f"文件: {filepath}")
    print(f"条目数: {len(entries)}")
    print(f"{'#':>4s}  {'大小':>10s}  {'偏移':>10s}  名称")
    print("-" * 60)

    total_size = 0
    for i, e in enumerate(entries):
        abs_offset = e.data_offset + DIR_DATA_BASE
        print(f"{i:4d}  {e.file_size:10d}  0x{abs_offset:08x}  {e.name}")
        total_size += e.file_size

    print("-" * 60)
    print(f"总计: {len(entries)} 个文件, {total_size:,} 字节")


def cmd_unpack(filepath, output_dir):
    """解包EMC文件到目录"""
    data, entries = read_emc(filepath)

    os.makedirs(output_dir, exist_ok=True)

    # 保存文件索引信息(用于封包)
    index_path = os.path.join(output_dir, '__emc_index__.txt')
    with open(index_path, 'w', encoding='utf-8') as idx:
        idx.write(f"# EMC Index - {os.path.basename(filepath)}\n")
        idx.write(f"# entry_count={len(entries)}\n")

        for i, e in enumerate(entries):
            abs_offset = e.data_offset + DIR_DATA_BASE

            # 提取文件数据
            file_data = data[abs_offset:abs_offset + e.file_size]

            # 确定输出路径(使用名称，避免路径冲突)
            # 如果有重名，加序号
            out_name = e.name
            out_path = os.path.join(output_dir, out_name)
            if os.path.exists(out_path):
                base, ext = os.path.splitext(out_name)
                out_name = f"{base}_{i}{ext}"
                out_path = os.path.join(output_dir, out_name)

            with open(out_path, 'wb') as fout:
                fout.write(file_data)

            # 写入索引行: 序号|原始路径|名称|时间戳|保留字段
            idx.write(f"{i}|{e.path}|{e.name}|{out_name}|{e.timestamp}|{e.reserved}\n")

            if (i + 1) % 50 == 0 or i == 0:
                print(f"  [{i+1}/{len(entries)}] {out_name} ({e.file_size} bytes)")

    print(f"\n解包完成: {len(entries)} 个文件 → {output_dir}/")
    print(f"索引文件: {index_path}")


def cmd_repack(input_dir, output_path, ref_emc=None):
    """从目录重新封包为EMC文件"""
    index_path = os.path.join(input_dir, '__emc_index__.txt')
    if not os.path.exists(index_path):
        print(f"错误: 找不到索引文件 {index_path}")
        print("请使用 unpack 命令生成的目录进行封包")
        sys.exit(1)

    # 读取索引
    entries_info = []
    with open(index_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('|')
            if len(parts) >= 6:
                idx = int(parts[0])
                orig_path = parts[1]
                orig_name = parts[2]
                out_name = parts[3]
                timestamp = int(parts[4])
                reserved = int(parts[5])
                entries_info.append({
                    'idx': idx,
                    'path': orig_path,
                    'name': orig_name,
                    'filename': out_name,
                    'timestamp': timestamp,
                    'reserved': reserved,
                })

    # 如果有参考EMC文件，读取原始文件头
    if ref_emc and os.path.exists(ref_emc):
        with open(ref_emc, 'rb') as f:
            ref_header = f.read(EMC_HEADER_SIZE)
    else:
        # 构造默认文件头
        ref_header = bytearray(EMC_HEADER_SIZE)
        ref_header[0:4] = b'VIST'
        ref_header[4:8] = struct.pack('<I', 0x1A)
        ref_header[8:12] = struct.pack('<I', 0x00020004)
        ref_header[0x10:0x10+22] = b'EMSAC-Binary Archive-2'

    # 读取所有文件数据
    file_datas = []
    for info in entries_info:
        fpath = os.path.join(input_dir, info['filename'])
        with open(fpath, 'rb') as f:
            file_datas.append(f.read())

    entry_count = len(entries_info)

    # 构建DirEntry段数据
    dir_data = bytearray()
    dir_data += struct.pack('<I', entry_count)

    # 计算DirEntry段总大小(需要先知道所有条目的大小来计算data_offset)
    # 先计算dir段大小
    dir_entries_size = 4  # entry_count
    for info in entries_info:
        path_bytes = info['path'].encode('ascii') + b'\x00'
        name_bytes = info['name'].encode('ascii') + b'\x00'
        dir_entries_size += ENTRY_FIXED_SIZE + len(path_bytes) + 4 + len(name_bytes)

    section_size = dir_entries_size
    # Round up to ensure alignment? Check original: 0xAA40
    # Original: 0xAA90 - 0x50 = 0xAA40

    # 计算数据区起始偏移(相对于DIR_DATA_BASE = 0x50)
    # data_region_abs = DIR_DATA_BASE + section_size
    # But there might be padding. In original: entries end exactly at section end.

    # 计算每个文件的data_offset
    # data_offset是相对于DIR_DATA_BASE(0x50)
    # 实际数据从 DIR_DATA_BASE + section_size 开始
    # 每个文件前有16字节前缀
    current_data_offset = section_size  # relative to 0x50
    for i, info in enumerate(entries_info):
        current_data_offset += FILE_PREFIX_SIZE  # 16-byte prefix
        info['data_offset'] = current_data_offset
        info['file_size'] = len(file_datas[i])
        current_data_offset += info['file_size']

    # 现在构建条目数据
    for i, info in enumerate(entries_info):
        path_bytes = info['path'].encode('ascii') + b'\x00'
        name_bytes = info['name'].encode('ascii') + b'\x00'

        # 固定0x24字节
        dir_data += struct.pack('<Q', info['file_size'])
        dir_data += struct.pack('<Q', info['reserved'])
        dir_data += struct.pack('<Q', info['data_offset'])
        dir_data += struct.pack('<Q', info['timestamp'])
        dir_data += struct.pack('<I', len(path_bytes))

        # 变长部分
        dir_data += path_bytes
        dir_data += struct.pack('<I', len(name_bytes))
        dir_data += name_bytes

    assert len(dir_data) == section_size, f"段大小不匹配: {len(dir_data)} vs {section_size}"

    # 构建完整文件
    with open(output_path, 'wb') as f:
        # 文件头
        f.write(ref_header)

        # DirEntry段头
        f.write(b'DirEntry')
        f.write(struct.pack('<Q', section_size))

        # DirEntry段数据
        f.write(dir_data)

        # 文件数据区
        for i, info in enumerate(entries_info):
            # 16字节前缀: [sequence u64] [file_size u64]
            f.write(struct.pack('<Q', i))
            f.write(struct.pack('<Q', info['file_size']))
            # 文件内容
            f.write(file_datas[i])

    total_size = os.path.getsize(output_path)
    print(f"封包完成: {entry_count} 个文件 → {output_path} ({total_size:,} bytes)")


def main():
    if len(sys.argv) < 3:
        print("EMC (EMSAC-Binary Archive-2) 解包/封包工具")
        print("适用引擎: EntisGLS / VIST (EScriptV2)")
        print()
        print("用法:")
        print(f"  {sys.argv[0]} list   <input.emc>                     列出文件")
        print(f"  {sys.argv[0]} unpack <input.emc> [output_dir]        解包")
        print(f"  {sys.argv[0]} repack <input_dir> <output.emc> [ref]  封包")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == 'list':
        cmd_list(sys.argv[2])
    elif cmd == 'unpack':
        out_dir = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(sys.argv[2])[0]
        cmd_unpack(sys.argv[2], out_dir)
    elif cmd == 'repack':
        if len(sys.argv) < 4:
            print("用法: repack <input_dir> <output.emc> [ref.emc]")
            sys.exit(1)
        ref = sys.argv[4] if len(sys.argv) > 4 else None
        cmd_repack(sys.argv[2], sys.argv[3], ref)
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)


if __name__ == '__main__':
    main()
