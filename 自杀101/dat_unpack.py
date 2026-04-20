#!/usr/bin/env python3
"""
ジサツのための101の方法 - Data.dat 解包工具
引擎格式逆向自反汇编代码 (FUN_00414040 / FUN_00414250)

DAT格式:
  [4 bytes] file_count ^ 0xFA261EFB
  [0x28 * file_count] 文件条目表:
    [0x20] 文件名 (XOR解密: byte[i] ^= (i*5 + 0xAC) & 0xFF)
    [4]    文件大小 ^ 0xFA261EFB
    [4]    文件偏移 (绝对偏移)
  [...]   文件数据 (基于文件名的循环XOR, 仅前0x2C00字节)
"""

import struct
import os
import sys


XOR_KEY = 0xFA261EFB


def decrypt_entry_name(raw: bytes) -> str:
    """解密文件条目的文件名部分 (0x20字节)"""
    dec = bytearray(raw)
    for i in range(0x20):
        dec[i] ^= (i * 5 + 0xAC) & 0xFF
    # 截断到null terminator
    try:
        end = dec.index(0)
    except ValueError:
        end = 0x20
    raw_name = dec[:end]
    # 优先尝试SJIS解码（日文文件名），fallback ASCII
    try:
        return raw_name.decode('cp932')
    except UnicodeDecodeError:
        return raw_name.decode('ascii', errors='replace')


def decrypt_entry_name_raw(raw: bytes) -> bytes:
    """解密文件条目的文件名部分 (0x20字节)，返回原始字节（截断到null）"""
    dec = bytearray(raw)
    for i in range(0x20):
        dec[i] ^= (i * 5 + 0xAC) & 0xFF
    try:
        end = dec.index(0)
    except ValueError:
        end = 0x20
    return bytes(dec[:end])


def char_upper_bytes(name: bytes) -> bytes:
    """模拟 CharUpperA: 仅将ASCII小写字母转大写，SJIS双字节保持不变"""
    result = bytearray(name)
    i = 0
    while i < len(result):
        b = result[i]
        # SJIS lead byte ranges: 0x81-0x9F, 0xE0-0xFC
        if (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC):
            i += 2  # 跳过双字节字符
        else:
            if 0x61 <= b <= 0x7A:  # a-z -> A-Z
                result[i] = b - 0x20
            i += 1
    return bytes(result)


def decrypt_file_data(data: bytearray, name_raw: bytes) -> bytearray:
    """
    解密文件数据 (FUN_00414250 中的XOR逻辑)
    name_raw: basename经过CharUpperA后的原始字节
    仅解密前 min(file_size, 0x2C00) 字节
    简化公式: data[i] ^= (name[i % name_len] + i) & 0xFF
    """
    name_bytes = name_raw
    name_len = len(name_bytes)
    if name_len == 0:
        return data
    
    decrypt_len = min(len(data), 0x2C00)
    
    for i in range(decrypt_len):
        j = i % name_len
        key = (name_bytes[j] + j + (i - j)) & 0xFF
        data[i] ^= key
    
    return data


def unpack_dat(dat_path: str, out_dir: str):
    with open(dat_path, 'rb') as f:
        dat_data = f.read()
    
    # 1. 读取文件数量
    raw_count = struct.unpack_from('<I', dat_data, 0)[0]
    file_count = raw_count ^ XOR_KEY
    print(f"文件数量: {file_count}")
    
    if file_count > 100000 or file_count <= 0:
        print(f"[!] 文件数量异常 ({file_count}), 可能格式不对或XOR key不同")
        return
    
    # 2. 读取文件条目表
    entries = []
    table_offset = 4
    for i in range(file_count):
        entry_offset = table_offset + i * 0x28
        # 文件名: 0x20字节 (解密后的原始字节 + 显示名)
        raw_name_enc = dat_data[entry_offset:entry_offset + 0x20]
        name_raw = decrypt_entry_name_raw(raw_name_enc)   # bytes
        name_display = decrypt_entry_name(raw_name_enc)     # str (cp932)
        # 文件大小: offset+0x20, 4字节, XOR加密
        raw_size = struct.unpack_from('<I', dat_data, entry_offset + 0x20)[0]
        file_size = raw_size ^ XOR_KEY
        # 文件偏移: offset+0x24, 4字节
        file_offset = struct.unpack_from('<I', dat_data, entry_offset + 0x24)[0]
        
        entries.append((name_raw, name_display, file_size, file_offset))
        print(f"  [{i:4d}] {name_display:<32s}  size={file_size:>10d}  offset=0x{file_offset:08X}")
    
    # 3. 提取文件
    os.makedirs(out_dir, exist_ok=True)
    
    for i, (name_raw, name_display, file_size, file_offset) in enumerate(entries):
        if not name_raw or file_size <= 0:
            print(f"  [{i}] 跳过空条目")
            continue
        
        if file_offset + file_size > len(dat_data):
            print(f"  [{i}] {name_display}: 偏移/大小越界, 跳过")
            continue
        
        raw = bytearray(dat_data[file_offset:file_offset + file_size])
        
        # 获取basename的原始字节，模拟CharUpperA后作为解密key
        if b'\\' in name_raw:
            basename_raw = name_raw.rsplit(b'\\', 1)[-1]
        else:
            basename_raw = name_raw
        key_bytes = char_upper_bytes(basename_raw)
        
        decrypted = decrypt_file_data(raw, key_bytes)
        
        # 用cp932显示名保存文件
        safe_name = name_display.replace('\\', os.sep).replace('/', os.sep)
        out_path = os.path.join(out_dir, safe_name)
        os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else out_dir, exist_ok=True)
        
        with open(out_path, 'wb') as f:
            f.write(decrypted)
    
    print(f"\n解包完成! 共 {file_count} 个文件 -> {out_dir}")


def list_dat(dat_path: str):
    """仅列出文件列表，不解包"""
    with open(dat_path, 'rb') as f:
        dat_data = f.read()
    
    raw_count = struct.unpack_from('<I', dat_data, 0)[0]
    file_count = raw_count ^ XOR_KEY
    print(f"文件数量: {file_count}")
    
    if file_count > 100000 or file_count <= 0:
        print(f"[!] 文件数量异常")
        return
    
    total_size = 0
    table_offset = 4
    for i in range(file_count):
        entry_offset = table_offset + i * 0x28
        raw_name = dat_data[entry_offset:entry_offset + 0x20]
        name = decrypt_entry_name(raw_name)
        raw_size = struct.unpack_from('<I', dat_data, entry_offset + 0x20)[0]
        file_size = raw_size ^ XOR_KEY
        file_offset = struct.unpack_from('<I', dat_data, entry_offset + 0x24)[0]
        total_size += file_size
        print(f"  [{i:4d}] {name:<32s}  size={file_size:>10d}  offset=0x{file_offset:08X}")
    
    print(f"\n总计 {file_count} 个文件, 解压总大小 {total_size:,} bytes")


def encrypt_entry_name(name_raw: bytes) -> bytes:
    """加密文件名字节到0x20字节的条目"""
    buf = bytearray(0x20)
    buf[:len(name_raw)] = name_raw[:0x20]
    for i in range(0x20):
        buf[i] ^= (i * 5 + 0xAC) & 0xFF
    return bytes(buf)


def encrypt_file_data(data: bytearray, name_raw: bytes) -> bytearray:
    """加密文件数据 (XOR是对称的，加密=解密)"""
    return decrypt_file_data(data, name_raw)


def repack_dat(input_dir: str, dat_path: str):
    """将目录中的文件重新封包为 .dat"""
    # 收集所有文件
    files = []
    for root, dirs, filenames in os.walk(input_dir):
        for fn in sorted(filenames):
            full_path = os.path.join(root, fn)
            rel_path = os.path.relpath(full_path, input_dir)
            with open(full_path, 'rb') as f:
                file_data = f.read()
            # 文件名需要保持原始编码(cp932)
            fn_bytes = fn.encode('cp932', errors='replace')
            files.append((fn_bytes, file_data))
    
    file_count = len(files)
    print(f"封包 {file_count} 个文件 -> {dat_path}")
    
    # 计算各偏移
    header_size = 4 + file_count * 0x28
    
    entries = []
    current_offset = header_size
    for fn_bytes, file_data in files:
        # 条目中存储的是大写的basename
        store_name = char_upper_bytes(fn_bytes)
        entries.append((store_name, len(file_data), current_offset, file_data))
        current_offset += len(file_data)
    
    # 写入
    with open(dat_path, 'wb') as f:
        # 文件数量
        f.write(struct.pack('<I', file_count ^ XOR_KEY))
        
        # 条目表
        for name_raw, size, offset, _ in entries:
            f.write(encrypt_entry_name(name_raw))
            f.write(struct.pack('<I', size ^ XOR_KEY))
            f.write(struct.pack('<I', offset))
        
        # 文件数据
        for name_raw, size, offset, file_data in entries:
            encrypted = encrypt_file_data(bytearray(file_data), name_raw)
            f.write(encrypted)
    
    print(f"封包完成: {dat_path} ({current_offset:,} bytes)")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"ジサツのための101の方法 - Data.dat 解包/封包工具")
        print(f"")
        print(f"用法:")
        print(f"  python {sys.argv[0]} list  <Data.dat>                # 列出文件")
        print(f"  python {sys.argv[0]} unpack <Data.dat> <output_dir>  # 解包")
        print(f"  python {sys.argv[0]} repack <input_dir> <output.dat> # 封包")
        print(f"")
        print(f"  (兼容旧用法)")
        print(f"  python {sys.argv[0]} <Data.dat>              # 列出文件")
        print(f"  python {sys.argv[0]} <Data.dat> <output_dir> # 解包")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == 'list' and len(sys.argv) >= 3:
        list_dat(sys.argv[2])
    elif cmd == 'unpack' and len(sys.argv) >= 4:
        unpack_dat(sys.argv[2], sys.argv[3])
    elif cmd == 'repack' and len(sys.argv) >= 4:
        repack_dat(sys.argv[2], sys.argv[3])
    elif os.path.exists(cmd):
        # 兼容旧用法
        if len(sys.argv) >= 3:
            unpack_dat(cmd, sys.argv[2])
        else:
            list_dat(cmd)
    else:
        print(f"未知命令或文件不存在: {cmd}")
        sys.exit(1)
