#!/usr/bin/env python3
"""
Interlude Engine data.img / *.pak 解包工具
逆向自 InterludeWin.exe

格式说明：
- 文件开头是索引表（Index Table），可能经过旋转密钥加密
- 索引表大小存储在偏移 0x0C 处（解密后），按 0x800 对齐读取
- 每个条目 0x14 (20) 字节：
    [0x00 - 0x0B] 12字节 文件名（大写，以\0结尾）
    [0x0C - 0x0F] 4字节 packed_offset:
        低11位 (& 0x7FF) = 块内子偏移
        高21位 (& 0xFFFFF800) = 0x800对齐的绝对偏移
    [0x10 - 0x13] 4字节 packed_size:
        低24位 (& 0xFFFFFF) = 文件大小
        高8位 (>> 24) = 数据卷编号 (0=主文件, 1=.001, 2=.002, ...)

加密算法：
    key = 0x6E86CC2E (初始密钥)
    对每个字节 i:
        data[i] += key & 0xFF
        key = ROL32(key, 1)  // 左旋转1位
        if (i & 5) != 0:
            key = ROL32(key, 1)  // 额外旋转1位
"""

import struct
import os
import sys
import ctypes


def rol32(val, n):
    """32位左旋转"""
    val &= 0xFFFFFFFF
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


def decrypt_data(data: bytearray, size: int) -> bytearray:
    """Interlude旋转密钥解密"""
    key = 0x6E86CC2E
    for i in range(size):
        c = key & 0xFF
        shifted = (key << 1) & 0xFFFFFFFF
        key = shifted | (key >> 31)
        data[i] = (data[i] + c) & 0xFF
        if (i & 5) != 0:
            shifted2 = (key << 1) & 0xFFFFFFFF
            key = shifted2 | (key >> 31)
    return data


def align_up(val, alignment):
    """向上对齐"""
    return (val + alignment - 1) & ~(alignment - 1)


def get_volume_filename(base_path: str, vol_index: int) -> str:
    """
    获取卷文件名
    vol_index=0: 主文件本身 (data.img)
    vol_index=1: data.001
    vol_index=2: data.002
    ...
    """
    if vol_index == 0:
        return base_path
    
    base_no_ext = os.path.splitext(base_path)[0]
    return f"{base_no_ext}.{vol_index:03d}"


def unpack(img_path: str, output_dir: str, verbose: bool = True):
    """
    解包 data.img 或 .pak 文件
    
    Args:
        img_path: data.img 或 .pak 文件路径
        output_dir: 输出目录
        verbose: 是否打印详细信息
    """
    if not os.path.exists(img_path):
        print(f"错误: 文件不存在: {img_path}")
        return
    
    os.makedirs(output_dir, exist_ok=True)
    
    file_size = os.path.getsize(img_path)
    print(f"[*] 打开文件: {img_path} ({file_size:,} 字节)")
    
    # 第一步：读取前 0x800 字节判断是否加密 + 获取索引表大小
    with open(img_path, 'rb') as f:
        header_raw = bytearray(f.read(0x800))
    
    first_byte = header_raw[0]
    is_encrypted = first_byte < 0x30
    
    if is_encrypted:
        print(f"[*] 检测到加密 (首字节=0x{first_byte:02X} < 0x30)，正在解密头部...")
        header = decrypt_data(bytearray(header_raw), 0x800)
    else:
        print(f"[*] 未加密 (首字节=0x{first_byte:02X} >= 0x30)")
        header = header_raw
    
    # 索引表大小在偏移 0x0C
    index_size = struct.unpack_from('<I', header, 0x0C)[0]
    index_aligned = align_up(index_size, 0x800)
    
    print(f"[*] 索引表大小: 0x{index_size:X} ({index_size:,} 字节)")
    print(f"[*] 索引表对齐大小: 0x{index_aligned:X}")
    
    # 第二步：读取完整索引表
    with open(img_path, 'rb') as f:
        index_data = bytearray(f.read(index_aligned))
    
    if is_encrypted:
        print(f"[*] 正在解密索引表...")
        index_data = decrypt_data(index_data, index_aligned)
    
    # 第三步：解析条目
    # 条目从偏移0开始，每条0x14字节
    # 遍历直到文件名首字节为\0 或 超出索引范围
    entries = []
    offset = 0
    entry_size = 0x14
    
    while offset + entry_size <= index_aligned:
        if index_data[offset] == 0:
            break
        
        # 解析文件名（前12字节）
        name_bytes = index_data[offset:offset+12]
        name_end = name_bytes.find(b'\x00')
        if name_end == -1:
            name = name_bytes.decode('ascii', errors='replace')
        else:
            name = name_bytes[:name_end].decode('ascii', errors='replace')
        
        # 解析 packed_offset 和 packed_size
        packed_offset = struct.unpack_from('<I', index_data, offset + 0x0C)[0]
        packed_size = struct.unpack_from('<I', index_data, offset + 0x10)[0]
        
        sub_offset = packed_offset & 0x7FF        # 块内子偏移
        abs_offset = packed_offset & 0xFFFFF800    # 绝对偏移（0x800对齐）
        data_size = packed_size & 0xFFFFFF         # 文件大小
        vol_index = (packed_size >> 24) & 0xFF     # 卷编号
        
        entries.append({
            'name': name,
            'packed_offset': packed_offset,
            'packed_size': packed_size,
            'abs_offset': abs_offset,
            'sub_offset': sub_offset,
            'data_size': data_size,
            'vol_index': vol_index,
            'file_offset': abs_offset + sub_offset,  # 实际文件偏移
        })
        
        offset += entry_size
    
    print(f"[*] 找到 {len(entries)} 个文件条目")
    
    if len(entries) == 0:
        print("[!] 没有找到文件条目，可能格式不对")
        return
    
    # 打印前几个条目用于验证
    print(f"\n[*] 前 {min(10, len(entries))} 个条目:")
    print(f"    {'文件名':<16} {'卷号':>4} {'偏移':>12} {'子偏移':>8} {'大小':>12}")
    print(f"    {'-'*16} {'-'*4} {'-'*12} {'-'*8} {'-'*12}")
    for i, e in enumerate(entries[:10]):
        print(f"    {e['name']:<16} {e['vol_index']:>4} 0x{e['abs_offset']:>08X} 0x{e['sub_offset']:>04X} {e['data_size']:>12,}")
    
    if len(entries) > 10:
        print(f"    ... 还有 {len(entries) - 10} 个文件")
    
    # 第四步：提取文件
    print(f"\n[*] 开始提取文件到: {output_dir}")
    
    # 打开需要的卷文件
    volume_handles = {}
    
    try:
        extracted = 0
        skipped = 0
        
        for i, entry in enumerate(entries):
            vol = entry['vol_index']
            vol_path = get_volume_filename(img_path, vol)
            
            # 按需打开卷文件
            if vol not in volume_handles:
                if os.path.exists(vol_path):
                    volume_handles[vol] = open(vol_path, 'rb')
                    if verbose:
                        print(f"[*] 打开卷文件: {vol_path}")
                else:
                    print(f"[!] 卷文件不存在: {vol_path}，跳过该卷中的文件")
                    volume_handles[vol] = None
            
            fh = volume_handles.get(vol)
            if fh is None:
                skipped += 1
                continue
            
            # 读取数据
            read_offset = entry['abs_offset']
            read_size_aligned = align_up(entry['data_size'] + entry['sub_offset'], 0x800)
            actual_offset = entry['file_offset']
            actual_size = entry['data_size']
            
            if actual_size == 0:
                skipped += 1
                continue
            
            try:
                fh.seek(actual_offset)
                file_data = fh.read(actual_size)
                
                if len(file_data) != actual_size:
                    print(f"[!] 警告: {entry['name']} 读取不完整 "
                          f"(期望 {actual_size}, 实际 {len(file_data)})")
                
                out_path = os.path.join(output_dir, entry['name'])
                with open(out_path, 'wb') as out_f:
                    out_f.write(file_data)
                
                extracted += 1
                
                if verbose and (extracted % 500 == 0 or extracted == 1):
                    print(f"    已提取: {extracted}/{len(entries)}")
                    
            except Exception as e:
                print(f"[!] 提取 {entry['name']} 失败: {e}")
                skipped += 1
        
        print(f"\n[*] 完成! 提取: {extracted}, 跳过: {skipped}, 总计: {len(entries)}")
        
    finally:
        for fh in volume_handles.values():
            if fh is not None:
                fh.close()


def list_files(img_path: str):
    """仅列出索引表中的文件，不提取"""
    if not os.path.exists(img_path):
        print(f"错误: 文件不存在: {img_path}")
        return
    
    file_size = os.path.getsize(img_path)
    
    with open(img_path, 'rb') as f:
        header_raw = bytearray(f.read(0x800))
    
    first_byte = header_raw[0]
    is_encrypted = first_byte < 0x30
    
    if is_encrypted:
        header = decrypt_data(bytearray(header_raw), 0x800)
    else:
        header = header_raw
    
    index_size = struct.unpack_from('<I', header, 0x0C)[0]
    index_aligned = align_up(index_size, 0x800)
    
    with open(img_path, 'rb') as f:
        index_data = bytearray(f.read(index_aligned))
    
    if is_encrypted:
        index_data = decrypt_data(index_data, index_aligned)
    
    entries = []
    offset = 0
    while offset + 0x14 <= index_aligned:
        if index_data[offset] == 0:
            break
        
        name_bytes = index_data[offset:offset+12]
        name_end = name_bytes.find(b'\x00')
        name = name_bytes[:name_end].decode('ascii', errors='replace') if name_end != -1 else name_bytes.decode('ascii', errors='replace')
        
        packed_offset = struct.unpack_from('<I', index_data, offset + 0x0C)[0]
        packed_size = struct.unpack_from('<I', index_data, offset + 0x10)[0]
        
        entries.append({
            'name': name,
            'vol': (packed_size >> 24) & 0xFF,
            'offset': (packed_offset & 0xFFFFF800) + (packed_offset & 0x7FF),
            'size': packed_size & 0xFFFFFF,
        })
        offset += 0x14
    
    print(f"文件: {img_path}")
    print(f"大小: {file_size:,} 字节")
    print(f"加密: {'是' if is_encrypted else '否'}")
    print(f"索引大小: 0x{index_size:X}")
    print(f"文件数: {len(entries)}")
    print()
    print(f"{'#':>5}  {'文件名':<16} {'卷':>3} {'偏移':>12} {'大小':>12}")
    print(f"{'-'*5}  {'-'*16} {'-'*3} {'-'*12} {'-'*12}")
    
    total_size = 0
    for i, e in enumerate(entries):
        print(f"{i:>5}  {e['name']:<16} {e['vol']:>3} 0x{e['offset']:>08X} {e['size']:>12,}")
        total_size += e['size']
    
    print(f"\n总大小: {total_size:,} 字节 ({total_size / 1024 / 1024:.1f} MB)")


def main():
    if len(sys.argv) < 2:
        print("Interlude Engine data.img / PAK 解包工具")
        print()
        print("用法:")
        print(f"  python {sys.argv[0]} <data.img|xxx.pak> [输出目录]    # 解包")
        print(f"  python {sys.argv[0]} -l <data.img|xxx.pak>            # 列出文件")
        print()
        print("示例:")
        print(f"  python {sys.argv[0]} data.img output_data")
        print(f"  python {sys.argv[0]} script.pak output_script")
        print(f"  python {sys.argv[0]} -l data.img")
        sys.exit(1)
    
    if sys.argv[1] == '-l':
        if len(sys.argv) < 3:
            print("错误: 请指定文件路径")
            sys.exit(1)
        list_files(sys.argv[2])
    else:
        img_path = sys.argv[1]
        if len(sys.argv) >= 3:
            output_dir = sys.argv[2]
        else:
            base = os.path.splitext(os.path.basename(img_path))[0]
            output_dir = f"{base}_unpacked"
        unpack(img_path, output_dir)


if __name__ == '__main__':
    main()
