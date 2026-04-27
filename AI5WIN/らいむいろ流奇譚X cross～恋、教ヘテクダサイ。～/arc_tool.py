#!/usr/bin/env python3
"""
Line2 Engine ARC Archive Tool (通用版)
=======================================
目标引擎: Line2 系列 (ライン2等多款游戏通用)
封包格式: .arc (Mes.Arc / Data.Arc / Bg.Arc / Music.Arc / Effect.Arc / Voice.Arc)

格式结构:
  [0x00]  uint32  file_count          文件数量
  [0x04]  entry[file_count]           索引表 (每条 0x28=40 字节, 加密)
  [data_start...]                     文件数据区 (紧密排列, 无间隙)

索引条目 (0x28 = 40 字节):
  [0x00]  char[32]  filename          文件名 (大写ASCII, \\0填充)
  [0x20]  uint32    file_size         文件大小
  [0x24]  uint32    file_offset       文件绝对偏移 (从arc文件头算起)

索引加密:
  1) 前 0x20 字节: 逐字节 XOR key_byte
  2) 偏移 0x20 的 uint32: XOR key_size
  3) 偏移 0x24 的 uint32: XOR key_offset
  三个密钥因游戏而异, 可从游戏EXE中自动提取。

用法:
  python arc_tool.py unpack <archive.arc> [output_dir] [--exe game.exe]
  python arc_tool.py pack   <input_dir> <output.arc>  [--exe game.exe]
  python arc_tool.py list   <archive.arc>              [--exe game.exe]
  python arc_tool.py scan   <game.exe>                 (扫描EXE中的密钥)

密钥指定方式 (优先级从高到低):
  1. --keys 0x03,0x14211597,0x10429634   手动指定
  2. --exe game.exe                       从EXE自动提取
  3. 输入目录下的 _keys.txt              封包时自动读取 (解包时自动保存)
  4. 内置默认值 (Line2: 0x03, 0x14211597, 0x10429634)
"""

import struct
import sys
import os
import argparse
from pathlib import Path

# ─── 默认密钥 (Line2) ────────────────────────────────────────────
DEFAULT_XOR_BYTE   = 0x03
DEFAULT_XOR_SIZE   = 0x14211597
DEFAULT_XOR_OFFSET = 0x10429634

ENTRY_SIZE = 0x28  # 40 bytes
NAME_SIZE  = 0x20  # 32 bytes


# ═══════════════════════════════════════════════════════════════════
#  密钥提取: 从 EXE 的机器码中自动搜索加密函数签名
# ═══════════════════════════════════════════════════════════════════

def scan_keys_from_exe(exe_path: str) -> list:
    """
    从EXE中搜索解密函数签名, 提取密钥三元组。
    
    签名模式 (x86):
      b3 XX                          ; mov bl, XOR_BYTE
      ...                            ; (XOR循环体)
      81 70 fc YY YY YY YY           ; xor dword ptr [eax-4], XOR_SIZE
      81 30 ZZ ZZ ZZ ZZ              ; xor dword ptr [eax],   XOR_OFFSET
    
    返回: [(xor_byte, xor_size, xor_offset), ...]
    """
    with open(exe_path, 'rb') as f:
        data = f.read()
    
    results = []
    # 搜索: 81 70 fc ?? ?? ?? ?? 81 30 ?? ?? ?? ??
    for i in range(len(data) - 13):
        if (data[i]   == 0x81 and data[i+1] == 0x70 and data[i+2] == 0xfc and
            data[i+7] == 0x81 and data[i+8] == 0x30):
            
            key_size   = struct.unpack_from('<I', data, i + 3)[0]
            key_offset = struct.unpack_from('<I', data, i + 9)[0]
            
            # 回溯搜索 mov bl, imm8 (b3 XX) — XOR_BYTE
            xor_byte = None
            for j in range(max(0, i - 30), i):
                if data[j] == 0xb3:
                    xor_byte = data[j + 1]
                    break
            
            if xor_byte is not None:
                # 额外验证: 附近应有 cmp reg, 0x20 和 add reg, 0x28
                context = data[max(0, i-30) : i+20]
                has_0x20 = b'\x83\xfa\x20' in context or b'\x83\xf9\x20' in context
                has_0x28 = b'\x83\xc0\x28' in context or b'\x83\xc1\x28' in context
                
                if has_0x20 or has_0x28:
                    results.append((xor_byte, key_size, key_offset))
    
    return results


# ═══════════════════════════════════════════════════════════════════
#  密钥文件读写
# ═══════════════════════════════════════════════════════════════════

def save_keys(directory: str, xor_byte: int, xor_size: int, xor_offset: int):
    """保存密钥到 _keys.txt"""
    path = os.path.join(directory, '_keys.txt')
    with open(path, 'w') as f:
        f.write(f"# Line2 ARC encryption keys (auto-saved)\n")
        f.write(f"xor_byte=0x{xor_byte:02x}\n")
        f.write(f"xor_size=0x{xor_size:08x}\n")
        f.write(f"xor_offset=0x{xor_offset:08x}\n")


def load_keys(directory: str):
    """从 _keys.txt 加载密钥, 返回 (xor_byte, xor_size, xor_offset) 或 None"""
    path = os.path.join(directory, '_keys.txt')
    if not os.path.exists(path):
        return None
    keys = {}
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            keys[k.strip()] = int(v.strip(), 0)
    if all(k in keys for k in ('xor_byte', 'xor_size', 'xor_offset')):
        return (keys['xor_byte'], keys['xor_size'], keys['xor_offset'])
    return None


# ═══════════════════════════════════════════════════════════════════
#  密钥解析: 根据命令行参数确定最终使用的密钥
# ═══════════════════════════════════════════════════════════════════

def resolve_keys(args, fallback_dir=None):
    """按优先级确定密钥"""
    # 1. --keys 手动指定
    if args.keys:
        parts = args.keys.split(',')
        if len(parts) != 3:
            print("Error: --keys 格式应为 xor_byte,xor_size,xor_offset")
            sys.exit(1)
        keys = tuple(int(p.strip(), 0) for p in parts)
        print(f"  密钥来源: --keys 手动指定")
        return keys
    
    # 2. --exe 从EXE提取
    if args.exe:
        found = scan_keys_from_exe(args.exe)
        if not found:
            print(f"Error: 在 {args.exe} 中未找到密钥签名")
            sys.exit(1)
        if len(found) > 1:
            print(f"Warning: 找到 {len(found)} 组密钥, 使用第一组")
        keys = found[0]
        print(f"  密钥来源: {args.exe}")
        return keys
    
    # 3. fallback_dir 中的 _keys.txt
    if fallback_dir:
        loaded = load_keys(fallback_dir)
        if loaded:
            print(f"  密钥来源: {os.path.join(fallback_dir, '_keys.txt')}")
            return loaded
    
    # 4. 默认值
    print(f"  密钥来源: 内置默认值 (Line2)")
    return (DEFAULT_XOR_BYTE, DEFAULT_XOR_SIZE, DEFAULT_XOR_OFFSET)


# ═══════════════════════════════════════════════════════════════════
#  索引加解密
# ═══════════════════════════════════════════════════════════════════

def decrypt_entry(raw: bytes, xor_byte: int, xor_size: int, xor_offset: int):
    """解密单个索引条目 → (filename, size, offset)"""
    buf = bytearray(raw)
    for j in range(NAME_SIZE):
        buf[j] ^= xor_byte
    size   = struct.unpack_from('<I', buf, 0x20)[0] ^ xor_size
    offset = struct.unpack_from('<I', buf, 0x24)[0] ^ xor_offset
    name   = bytes(buf[:NAME_SIZE]).split(b'\x00')[0].decode('ascii', errors='replace')
    return (name, size, offset)


def encrypt_entry(name: str, size: int, offset: int,
                  xor_byte: int, xor_size: int, xor_offset: int) -> bytes:
    """加密单个索引条目 → 0x28 bytes"""
    buf = bytearray(ENTRY_SIZE)
    name_bytes = name.encode('ascii')
    if len(name_bytes) > NAME_SIZE:
        raise ValueError(f"文件名过长 (>{NAME_SIZE}字节): {name}")
    buf[:len(name_bytes)] = name_bytes
    struct.pack_into('<I', buf, 0x20, size ^ xor_size)
    struct.pack_into('<I', buf, 0x24, offset ^ xor_offset)
    for j in range(NAME_SIZE):
        buf[j] ^= xor_byte
    return bytes(buf)


# ═══════════════════════════════════════════════════════════════════
#  命令实现
# ═══════════════════════════════════════════════════════════════════

def cmd_scan(args):
    """扫描EXE中的密钥"""
    found = scan_keys_from_exe(args.exe_path)
    if not found:
        print(f"在 {args.exe_path} 中未找到 Line2 ARC 密钥签名。")
        return
    for i, (xb, xs, xo) in enumerate(found):
        print(f"  密钥组 #{i+1}:")
        print(f"    xor_byte   = 0x{xb:02x}")
        print(f"    xor_size   = 0x{xs:08x}")
        print(f"    xor_offset = 0x{xo:08x}")
        print(f"    --keys 参数: --keys 0x{xb:02x},0x{xs:08x},0x{xo:08x}")


def cmd_list(args):
    """列出arc内所有文件"""
    keys = resolve_keys(args)
    xor_byte, xor_size, xor_offset = keys
    print(f"  xor_byte=0x{xor_byte:02x}  xor_size=0x{xor_size:08x}  xor_offset=0x{xor_offset:08x}")
    print()

    with open(args.arc_path, 'rb') as f:
        data = f.read()
    
    count = struct.unpack_from('<I', data, 0)[0]
    entries = []
    for i in range(count):
        raw = data[4 + i * ENTRY_SIZE: 4 + (i + 1) * ENTRY_SIZE]
        entries.append(decrypt_entry(raw, xor_byte, xor_size, xor_offset))
    
    # sanity check
    data_start = 4 + count * ENTRY_SIZE
    sorted_entries = sorted(entries, key=lambda e: e[2])
    if sorted_entries and sorted_entries[0][2] != data_start:
        print(f"  ⚠ Warning: 首文件偏移 {sorted_entries[0][2]:#x} ≠ 预期 {data_start:#x}")
        print(f"  密钥可能不正确！请用 --exe 或 --keys 指定。")
        print()

    print(f"{'Name':32s} {'Offset':>10s} {'Size':>10s}")
    print("-" * 56)
    total = 0
    for name, size, offset in sorted_entries:
        print(f"{name:32s} {offset:#010x} {size:>10,d}")
        total += size
    print("-" * 56)
    print(f"Total: {count} files, {total:,} bytes")


def cmd_unpack(args):
    """解包arc文件"""
    keys = resolve_keys(args)
    xor_byte, xor_size, xor_offset = keys
    print(f"  xor_byte=0x{xor_byte:02x}  xor_size=0x{xor_size:08x}  xor_offset=0x{xor_offset:08x}")

    with open(args.arc_path, 'rb') as f:
        data = f.read()

    count = struct.unpack_from('<I', data, 0)[0]
    entries = []
    for i in range(count):
        raw = data[4 + i * ENTRY_SIZE: 4 + (i + 1) * ENTRY_SIZE]
        entries.append(decrypt_entry(raw, xor_byte, xor_size, xor_offset))

    # sanity check
    data_start = 4 + count * ENTRY_SIZE
    sorted_entries = sorted(entries, key=lambda e: e[2])
    if sorted_entries and sorted_entries[0][2] != data_start:
        print(f"  ⚠ Warning: 首文件偏移 {sorted_entries[0][2]:#x} ≠ 预期 {data_start:#x}")
        print(f"  密钥可能不正确！")
        resp = input("  继续? [y/N] ").strip().lower()
        if resp != 'y':
            return

    out_dir = args.output or os.path.splitext(args.arc_path)[0]
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, '_index.txt'), 'w', encoding='utf-8') as f:
        for name, _, _ in entries:
            f.write(f"{name}\n")

    save_keys(out_dir, xor_byte, xor_size, xor_offset)

    for i, (name, size, offset) in enumerate(entries):
        file_data = data[offset: offset + size]
        with open(os.path.join(out_dir, name), 'wb') as f:
            f.write(file_data)
        print(f"  [{i+1:3d}/{count}] {name} ({size:,} bytes)")

    print(f"\nDone: {count} files → {out_dir}/")


def cmd_pack(args):
    """封包目录为arc"""
    keys = resolve_keys(args, fallback_dir=args.input_dir)
    xor_byte, xor_size, xor_offset = keys
    print(f"  xor_byte=0x{xor_byte:02x}  xor_size=0x{xor_size:08x}  xor_offset=0x{xor_offset:08x}")

    in_dir = args.input_dir
    index_path = os.path.join(in_dir, '_index.txt')
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            names = [line.strip() for line in f if line.strip()]
        existing = set(names)
        for fn in sorted(os.listdir(in_dir)):
            if fn.startswith('_'):
                continue
            if fn not in existing:
                names.append(fn)
                print(f"  [新增] {fn}")
        names = [n for n in names if os.path.exists(os.path.join(in_dir, n))]
    else:
        names = sorted(fn for fn in os.listdir(in_dir) if not fn.startswith('_'))

    count = len(names)
    if count == 0:
        print("Error: 无文件可封包")
        return

    data_start = 4 + count * ENTRY_SIZE
    entries = []
    file_datas = []
    current_offset = data_start

    for name in names:
        with open(os.path.join(in_dir, name), 'rb') as f:
            fdata = f.read()
        entries.append((name, len(fdata), current_offset))
        file_datas.append(fdata)
        current_offset += len(fdata)

    with open(args.arc_path, 'wb') as f:
        f.write(struct.pack('<I', count))
        for name, size, offset in entries:
            f.write(encrypt_entry(name, size, offset, xor_byte, xor_size, xor_offset))
        for fdata in file_datas:
            f.write(fdata)

    total = sum(len(d) for d in file_datas)
    print(f"Packed {count} files ({total:,} bytes) → {args.arc_path}")

    # 验证
    verify = []
    with open(args.arc_path, 'rb') as f:
        vdata = f.read()
    vc = struct.unpack_from('<I', vdata, 0)[0]
    for i in range(vc):
        raw = vdata[4 + i * ENTRY_SIZE: 4 + (i + 1) * ENTRY_SIZE]
        verify.append(decrypt_entry(raw, xor_byte, xor_size, xor_offset))
    
    ok = True
    for (n1, s1, o1), (n2, s2, o2) in zip(entries, verify):
        if n1 != n2 or s1 != s2 or o1 != o2:
            print(f"  ✗ Verify failed: {n1}")
            ok = False
    if ok:
        print("Round-trip verification passed ✓")


# ═══════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Line2 Engine ARC Archive Tool (通用版)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest='command')

    p_scan = sub.add_parser('scan', help='扫描EXE中的ARC密钥')
    p_scan.add_argument('exe_path', help='游戏EXE路径')

    p_list = sub.add_parser('list', help='列出ARC内文件')
    p_list.add_argument('arc_path')
    p_list.add_argument('--exe', help='游戏EXE (自动提取密钥)')
    p_list.add_argument('--keys', help='手动密钥: byte,size,offset')

    p_unp = sub.add_parser('unpack', help='解包ARC')
    p_unp.add_argument('arc_path')
    p_unp.add_argument('output', nargs='?', help='输出目录')
    p_unp.add_argument('--exe', help='游戏EXE (自动提取密钥)')
    p_unp.add_argument('--keys', help='手动密钥: byte,size,offset')

    p_pack = sub.add_parser('pack', help='封包为ARC')
    p_pack.add_argument('input_dir')
    p_pack.add_argument('arc_path')
    p_pack.add_argument('--exe', help='游戏EXE (自动提取密钥)')
    p_pack.add_argument('--keys', help='手动密钥: byte,size,offset')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    {'scan': cmd_scan, 'list': cmd_list,
     'unpack': cmd_unpack, 'pack': cmd_pack}[args.command](args)


if __name__ == '__main__':
    main()
