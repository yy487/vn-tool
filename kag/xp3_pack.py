#!/usr/bin/env python3
"""
XP3 明文封包工具
创建未加密的 patch.xp3 覆盖包

XP3结构:
  Header (11B): 'XP3\r\n \n\x1a\x8b\x67\x01'
  u64 index_offset (指向文件末尾的索引区)
  u64 padding (0)
  文件数据区...
  文件索引区(在末尾)
"""
import struct
import zlib
from pathlib import Path
from typing import List, Dict


XP3_SIGNATURE = b'XP3\r\n \n\x1a\x8b\x67\x01'


def pack_xp3(file_list: List[Path], output_xp3: Path):
    """
    打包文件列表为XP3
    file_list: 要打包的文件路径列表
    output_xp3: 输出的xp3文件路径
    """
    
    # 收集文件信息
    file_entries = []
    
    for fpath in file_list:
        if not fpath.exists():
            print(f'警告: 文件不存在 {fpath}')
            continue
        
        with open(fpath, 'rb') as f:
            data = f.read()
        
        # 使用相对路径作为存档内路径
        archive_name = fpath.name
        
        entry = {
            'name': archive_name,
            'data': data,
            'size': len(data)
        }
        
        file_entries.append(entry)
        print(f'添加: {archive_name} ({len(data)} 字节)')
    
    if not file_entries:
        print('错误: 没有文件可打包')
        return
    
    # 开始写入XP3
    with open(output_xp3, 'wb') as xp3:
        # 写入头部签名
        xp3.write(XP3_SIGNATURE)
        
        # 预留index_offset位置(8字节)
        index_offset_pos = xp3.tell()
        xp3.write(struct.pack('<Q', 0))  # 占位
        
        # 预留padding(8字节,通常为0)
        xp3.write(struct.pack('<Q', 0))
        
        # 写入文件数据,记录每个文件的偏移
        for entry in file_entries:
            entry['offset'] = xp3.tell()
            xp3.write(entry['data'])
        
        # 记录索引区开始位置
        index_start = xp3.tell()
        
        # 构建索引区
        index_data = build_index(file_entries)
        
        # 写入索引区
        xp3.write(index_data)
        
        # 回填index_offset
        xp3.seek(index_offset_pos)
        xp3.write(struct.pack('<Q', index_start))
    
    print(f'\n封包完成: {output_xp3} ({len(file_entries)} 个文件)')


def build_index(file_entries: List[Dict]) -> bytes:
    """
    构建XP3索引区
    
    索引区结构:
      u8 compressed_flag (0=未压缩, 1=zlib压缩)
      u64 compressed_size
      u64 original_size
      索引数据 (可能被压缩)
    
    索引数据结构:
      对每个文件:
        'File' chunk
        'info' chunk  (u32 flags, u64 orig_size, u64 packed_size, u16 name_len, name)
        'segm' chunk  (u32 flags, u64 offset, u64 orig_size, u64 packed_size)
        'adlr' chunk  (u32 adler32)
    """
    
    index_chunks = []
    
    for entry in file_entries:
        # 构建单个文件的索引块
        file_chunk = build_file_chunk(entry)
        index_chunks.append(file_chunk)
    
    # 合并所有文件的索引块
    index_raw = b''.join(index_chunks)
    
    # 不压缩索引(flag=0)
    compressed_flag = 0
    compressed_data = index_raw
    
    # 构建最终索引区
    index_header = struct.pack('<BQQ', 
                               compressed_flag,
                               len(compressed_data),
                               len(index_raw))
    
    return index_header + compressed_data


def build_file_chunk(entry: Dict) -> bytes:
    """构建单个文件的File块"""
    
    chunks = []
    
    # info chunk
    info_chunk = build_info_chunk(entry)
    chunks.append(info_chunk)
    
    # segm chunk
    segm_chunk = build_segm_chunk(entry)
    chunks.append(segm_chunk)
    
    # adlr chunk
    adlr_chunk = build_adlr_chunk(entry)
    chunks.append(adlr_chunk)
    
    # 合并所有chunk
    file_data = b''.join(chunks)
    
    # File chunk header: 'File' + u64 size
    file_chunk = b'File' + struct.pack('<Q', len(file_data)) + file_data
    
    return file_chunk


def build_info_chunk(entry: Dict) -> bytes:
    """info chunk: 文件基本信息"""
    
    # 文件名转UTF-16LE
    name_utf16 = entry['name'].encode('utf-16le')
    
    # info数据: u32 flags, u64 orig_size, u64 packed_size, u16 name_len, name
    flags = 0  # 未压缩
    orig_size = entry['size']
    packed_size = entry['size']
    name_len = len(name_utf16) // 2  # UTF-16字符数
    
    info_data = struct.pack('<IQQH', flags, orig_size, packed_size, name_len)
    info_data += name_utf16
    
    # info chunk header: 'info' + u64 size
    info_chunk = b'info' + struct.pack('<Q', len(info_data)) + info_data
    
    return info_chunk


def build_segm_chunk(entry: Dict) -> bytes:
    """segm chunk: 文件数据段信息"""
    
    # segm数据: u32 flags, u64 offset, u64 orig_size, u64 packed_size
    flags = 0  # 未压缩
    offset = entry['offset']
    orig_size = entry['size']
    packed_size = entry['size']
    
    segm_data = struct.pack('<IQQQ', flags, offset, orig_size, packed_size)
    
    # segm chunk header: 'segm' + u64 size (固定0x1C)
    segm_chunk = b'segm' + struct.pack('<Q', 0x1C) + segm_data
    
    return segm_chunk


def build_adlr_chunk(entry: Dict) -> bytes:
    """adlr chunk: 文件校验和"""
    
    # 计算adler32
    adler = zlib.adler32(entry['data']) & 0xFFFFFFFF
    
    # adlr数据: u32 adler32
    adlr_data = struct.pack('<I', adler)
    
    # adlr chunk header: 'adlr' + u64 size (固定4)
    adlr_chunk = b'adlr' + struct.pack('<Q', 4) + adlr_data
    
    return adlr_chunk


def pack_directory(input_dir: Path, output_xp3: Path, pattern='*.ks'):
    """打包整个目录"""
    
    input_dir = Path(input_dir)
    file_list = sorted(input_dir.glob(pattern))
    
    if not file_list:
        print(f'错误: 在 {input_dir} 中找不到 {pattern} 文件')
        return
    
    print(f'找到 {len(file_list)} 个文件')
    pack_xp3(file_list, output_xp3)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 3:
        print('用法: python xp3_pack.py <输入目录> <输出xp3> [文件模式]')
        print('示例: python xp3_pack.py ./translated patch.xp3')
        print('      python xp3_pack.py ./translated patch.xp3 "*.ks"')
        sys.exit(1)
    
    input_dir = Path(sys.argv[1])
    output_xp3 = Path(sys.argv[2])
    pattern = sys.argv[3] if len(sys.argv) > 3 else '*.ks'
    
    pack_directory(input_dir, output_xp3, pattern)
