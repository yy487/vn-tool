#!/usr/bin/env python3
"""AI5WIN v3 ARC 解包/封包工具 (Interlude 等)
纯索引加密解密,不含LZSS解压缩——文件原样提取/打包。

用法:
  python ai5win_arc_tool.py unpack <input.ARC> <output_dir>
  python ai5win_arc_tool.py pack   <input_dir>  <output.ARC>

ARC 格式:
  +0x00     uint32    file_count
  +0x04     Entry[N]  index_table (N × 0x1C, 全部加密)
  +idx_end  ...       file_data

Entry (0x1C = 28 bytes):
  [0x00-0x13] 20B  filename  每字节 XOR 0x03, null 填充
  [0x14-0x17]  4B  size      XOR 0x56428101
  [0x18-0x1B]  4B  offset    XOR 0x32388531 (绝对偏移)
"""
import struct, sys, os

# ─── 加密常量 (从 EXE FUN_00406e90 提取) ───
NAME_XOR   = 0x03
XOR_SIZE   = 0x56428101
XOR_OFFSET = 0x32388531
ENTRY_SIZE = 0x1C
NAME_SIZE  = 0x14  # 20 bytes

def dec_name(raw):
    out = bytearray(NAME_SIZE)
    for i in range(NAME_SIZE):
        out[i] = raw[i] ^ NAME_XOR
    return out.rstrip(b'\x00').decode('ascii')

def enc_name(name):
    padded = name.encode('ascii').ljust(NAME_SIZE, b'\x00')[:NAME_SIZE]
    return bytes(b ^ NAME_XOR for b in padded)

def dec_u32(raw_val, xor_key):
    return raw_val ^ xor_key

def enc_u32(plain_val, xor_key):
    return plain_val ^ xor_key

# ─── 解包 ───
def unpack_arc(arc_path, out_dir):
    with open(arc_path, 'rb') as f:
        data = f.read()

    count = struct.unpack_from('<I', data, 0)[0]
    print(f"文件数: {count}")
    os.makedirs(out_dir, exist_ok=True)
    names = []

    for i in range(count):
        base = 4 + i * ENTRY_SIZE
        entry = data[base:base + ENTRY_SIZE]

        name   = dec_name(entry[0:NAME_SIZE])
        size   = dec_u32(struct.unpack_from('<I', entry, 0x14)[0], XOR_SIZE)
        offset = dec_u32(struct.unpack_from('<I', entry, 0x18)[0], XOR_OFFSET)

        fdata = data[offset:offset + size]
        with open(os.path.join(out_dir, name), 'wb') as fout:
            fout.write(fdata)

        names.append(name)
        if (i + 1) % 500 == 0 or i + 1 == count:
            print(f"  [{i+1:4d}/{count}]")

    with open(os.path.join(out_dir, '__filelist.txt'), 'w') as f:
        f.write('\n'.join(names) + '\n')

    print(f"\n解包完成: {count} 文件 → {out_dir}")

# ─── 封包 ───
def pack_arc(in_dir, arc_path):
    lst_path = os.path.join(in_dir, '__filelist.txt')
    if os.path.exists(lst_path):
        names = [l.strip() for l in open(lst_path) if l.strip()]
    else:
        names = sorted(f for f in os.listdir(in_dir)
                       if not f.startswith('__') and os.path.isfile(os.path.join(in_dir, f)))

    count = len(names)
    idx_end = 4 + count * ENTRY_SIZE

    files = []
    cur_offset = idx_end
    for name in names:
        fdata = open(os.path.join(in_dir, name), 'rb').read()
        files.append((name, fdata, cur_offset))
        cur_offset += len(fdata)

    out = bytearray(struct.pack('<I', count))
    for name, fdata, offset in files:
        out += enc_name(name)
        out += struct.pack('<I', enc_u32(len(fdata), XOR_SIZE))
        out += struct.pack('<I', enc_u32(offset, XOR_OFFSET))

    for name, fdata, offset in files:
        out += fdata

    os.makedirs(os.path.dirname(arc_path) or '.', exist_ok=True)
    with open(arc_path, 'wb') as f:
        f.write(out)

    print(f"封包完成: {count} 文件 → {arc_path} ({len(out):,} bytes)")

# ─── 入口 ───
if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == 'unpack':
        unpack_arc(sys.argv[2], sys.argv[3])
    elif cmd == 'pack':
        pack_arc(sys.argv[2], sys.argv[3])
    else:
        print(f"未知命令: {cmd}")
        print(__doc__); sys.exit(1)
