"""
C1WIN/C1WIS DAT Archive Tool (天巫女姫 C1WIN Engine)
  解包/封包 .DAT 存档文件
  
  格式说明:
    .LST 索引文件: 每条目 22 字节
      +0x00: char[14]  文件名 (ASCII, null-padded)
      +0x0E: u32       DAT内偏移
      +0x12: u32       文件大小
    .TAG 标签文件: 每条目 16 字节
      +0x00: u16       类型标记
      +0x02: u16       tag高位
      +0x04: u16       tag低位
      +0x06: 10 bytes  保留(0)
    .DAT 数据文件: 文件数据按偏移顺序排列

  使用方法:
    解包: python c1win_dat_tool.py unpack <basename> [output_dir]
    列表: python c1win_dat_tool.py list <basename>
    封包: python c1win_dat_tool.py repack <basename> <input_dir> [output_basename]
    
  示例:
    python c1win_dat_tool.py unpack C1WIN ./extracted
    python c1win_dat_tool.py list C1WIS
    python c1win_dat_tool.py repack C1WIN ./modified C1WIN_NEW
"""

import os
import sys
import struct
from pathlib import Path

ENTRY_SIZE_LST = 22
ENTRY_SIZE_TAG = 16
FILENAME_LEN = 14

def parse_lst(lst_path):
    """解析 .LST 索引文件"""
    with open(lst_path, 'rb') as f:
        data = f.read()
    
    n = len(data) // ENTRY_SIZE_LST
    entries = []
    for i in range(n):
        off = i * ENTRY_SIZE_LST
        raw = data[off:off+ENTRY_SIZE_LST]
        name_raw = raw[0:FILENAME_LEN]
        dat_offset = struct.unpack_from('<I', raw, 14)[0]
        file_size = struct.unpack_from('<I', raw, 18)[0]
        
        # 判断有效性: 文件名应该是可打印ASCII
        name_end = name_raw.find(b'\x00')
        if name_end < 0:
            name_end = FILENAME_LEN
        name_bytes = name_raw[:name_end]
        
        # 检查文件名是否为有效ASCII
        is_valid = len(name_bytes) > 0 and all(0x20 <= b < 0x7f for b in name_bytes)
        
        if is_valid:
            name = name_bytes.decode('ascii')
        else:
            name = None  # 无效条目
        
        entries.append({
            'index': i,
            'name': name,
            'name_raw': name_raw,
            'offset': dat_offset,
            'size': file_size,
            'valid': is_valid,
        })
    
    return entries

def parse_tag(tag_path):
    """解析 .TAG 标签文件"""
    with open(tag_path, 'rb') as f:
        data = f.read()
    
    n = len(data) // ENTRY_SIZE_TAG
    tags = []
    for i in range(n):
        off = i * ENTRY_SIZE_TAG
        raw = data[off:off+ENTRY_SIZE_TAG]
        vals = struct.unpack_from('<8H', raw, 0)
        tags.append({
            'index': i,
            'type': vals[0],
            'tag_hi': vals[1],
            'tag_lo': vals[2],
            'raw': raw,
        })
    
    return tags

def cmd_list(basename):
    """列出存档内容"""
    lst_path = f"{basename}.LST"
    tag_path = f"{basename}.TAG"
    dat_path = f"{basename}.DAT"
    
    entries = parse_lst(lst_path)
    tags = parse_tag(tag_path) if os.path.exists(tag_path) else []
    
    dat_size = os.path.getsize(dat_path) if os.path.exists(dat_path) else 0
    
    print(f"Archive: {basename}")
    print(f"  LST: {lst_path} ({len(entries)} entries)")
    print(f"  TAG: {tag_path} ({len(tags)} entries)")
    print(f"  DAT: {dat_path} ({dat_size:,} bytes)")
    print()
    
    valid_count = 0
    total_size = 0
    print(f"{'#':>4s}  {'Filename':16s}  {'Offset':>10s}  {'Size':>10s}  {'Tag':>12s}")
    print("-" * 62)
    
    for i, entry in enumerate(entries):
        tag_str = ""
        if i < len(tags):
            t = tags[i]
            tag_str = f"{t['type']:04x}:{t['tag_hi']:04x}{t['tag_lo']:04x}"
        
        if entry['valid']:
            print(f"{i:4d}  {entry['name']:16s}  0x{entry['offset']:08x}  {entry['size']:10,d}  {tag_str}")
            valid_count += 1
            total_size += entry['size']
        else:
            print(f"{i:4d}  {'<invalid>':16s}  0x{entry['offset']:08x}  {entry['size']:10,d}  {tag_str}  [SKIP]")
    
    print(f"\n有效文件: {valid_count}/{len(entries)}, 总大小: {total_size:,} bytes")

def cmd_unpack(basename, output_dir):
    """解包存档"""
    lst_path = f"{basename}.LST"
    dat_path = f"{basename}.DAT"
    
    entries = parse_lst(lst_path)
    
    os.makedirs(output_dir, exist_ok=True)
    
    valid_entries = [e for e in entries if e['valid']]
    print(f"解包 {basename}: {len(valid_entries)} 个文件")
    
    with open(dat_path, 'rb') as dat_f:
        for entry in valid_entries:
            name = entry['name']
            offset = entry['offset']
            size = entry['size']
            
            dat_f.seek(offset)
            data = dat_f.read(size)
            
            if len(data) != size:
                print(f"  警告: {name} 读取不完整 ({len(data)}/{size})")
                continue
            
            out_path = os.path.join(output_dir, name)
            with open(out_path, 'wb') as out_f:
                out_f.write(data)
            
            print(f"  {name:16s}  {size:10,d} bytes")
    
    print(f"\n完成! 已解包到 {output_dir}/")

def cmd_repack(basename, input_dir, output_basename):
    """封包存档 (保持原始LST条目顺序)"""
    lst_path = f"{basename}.LST"
    tag_path = f"{basename}.TAG"
    
    entries = parse_lst(lst_path)
    
    # 读取原始TAG
    tag_data = b''
    if os.path.exists(tag_path):
        with open(tag_path, 'rb') as f:
            tag_data = f.read()
    
    out_lst = f"{output_basename}.LST"
    out_tag = f"{output_basename}.TAG"
    out_dat = f"{output_basename}.DAT"
    
    print(f"封包 {input_dir}/ -> {output_basename}.*")
    
    new_lst = bytearray()
    new_dat_offset = 0
    
    with open(out_dat, 'wb') as dat_f:
        for entry in entries:
            if not entry['valid']:
                # 保留无效条目的原始LST数据
                raw = entry['name_raw'] + struct.pack('<II', entry['offset'], entry['size'])
                new_lst += raw
                continue
            
            name = entry['name']
            file_path = os.path.join(input_dir, name)
            
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                print(f"  {name:16s}  {len(file_data):10,d} bytes")
            else:
                # 如果修改目录中没有这个文件，从原始DAT读取
                orig_dat = f"{basename}.DAT"
                with open(orig_dat, 'rb') as f:
                    f.seek(entry['offset'])
                    file_data = f.read(entry['size'])
                print(f"  {name:16s}  {len(file_data):10,d} bytes (original)")
            
            # 写入数据
            dat_f.write(file_data)
            
            # 构造LST条目
            name_padded = name.encode('ascii').ljust(FILENAME_LEN, b'\x00')[:FILENAME_LEN]
            lst_entry = name_padded + struct.pack('<II', new_dat_offset, len(file_data))
            new_lst += lst_entry
            
            new_dat_offset += len(file_data)
    
    # 写入LST
    with open(out_lst, 'wb') as f:
        f.write(new_lst)
    
    # 复制TAG (不修改)
    if tag_data:
        with open(out_tag, 'wb') as f:
            f.write(tag_data)
    
    print(f"\n完成! 输出: {out_lst}, {out_tag}, {out_dat}")

def print_usage():
    print(__doc__)

def main():
    if len(sys.argv) < 3:
        print_usage()
        return
    
    cmd = sys.argv[1].lower()
    basename = sys.argv[2]
    
    if cmd == 'list':
        cmd_list(basename)
    elif cmd == 'unpack':
        output_dir = sys.argv[3] if len(sys.argv) > 3 else f"{basename}_extracted"
        cmd_unpack(basename, output_dir)
    elif cmd == 'repack':
        if len(sys.argv) < 4:
            print("用法: c1win_dat_tool.py repack <basename> <input_dir> [output_basename]")
            return
        input_dir = sys.argv[3]
        output_basename = sys.argv[4] if len(sys.argv) > 4 else f"{basename}_new"
        cmd_repack(basename, input_dir, output_basename)
    else:
        print(f"未知命令: {cmd}")
        print_usage()

if __name__ == '__main__':
    main()
