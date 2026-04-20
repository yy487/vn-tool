#!/usr/bin/env python3
"""AI5WIN v3 ARC 解包/封包工具 (あしたの雪之丞2)
纯索引加密解密,不含LZSS解压缩——文件原样提取/打包。

用法:
  python ai5win_arc_tool.py unpack <input.ARC> <output_dir>
  python ai5win_arc_tool.py pack   <input_dir>  <output.ARC>

ARC 格式:
  +0x00     uint32    file_count
  +0x04     Entry[N]  index_table (N × 0x20, 全部加密)
  +idx_end  ...       file_data

Entry (0x20 = 32 bytes):
  [0x00-0x17] 24B  filename  XOR key[i%8]
  [0x18-0x1B]  4B  size      XOR 0x7D306EF1 + bswap16pairs
  [0x1C-0x1F]  4B  offset    XOR 0x6EF1AB92 + bswap16pairs (绝对偏移)

XOR key (EXE .data 0x453304): 51 92 AB F1 6E 30 7D 48
"""
import struct, sys, os

# ─── 加密常量 ───
ARC_KEY = bytes([0x51, 0x92, 0xAB, 0xF1, 0x6E, 0x30, 0x7D, 0x48])
XOR_SIZE   = 0x7D306EF1   # CONCAT22(key[5:7]_u16LE, key[3:5]_u16LE)
XOR_OFFSET = 0x6EF1AB92   # CONCAT22(key[3:5]_u16LE, key[1:3]_u16LE)

def bswap16pairs(v):
    """16位半字内字节翻转: AABBCCDD → BBAADDCC"""
    v &= 0xFFFFFFFF
    return (((v >> 8) ^ (v << 8)) & 0x00FF00FF ^ (v << 8)) & 0xFFFFFFFF

def dec_name(raw):
    """解密文件名 (24字节 XOR key[i%8])"""
    out = bytearray(24)
    for i in range(24):
        out[i] = raw[i] ^ ARC_KEY[i % 8]
    return out.rstrip(b'\x00').decode('ascii')

def enc_name(name):
    """加密文件名"""
    padded = name.encode('ascii').ljust(24, b'\x00')[:24]
    out = bytearray(24)
    for i in range(24):
        out[i] = padded[i] ^ ARC_KEY[i % 8]
    return bytes(out)

def dec_u32(raw_val, xor_key):
    """解密 size/offset: XOR → bswap16pairs"""
    return bswap16pairs(raw_val ^ xor_key)

def enc_u32(plain_val, xor_key):
    """加密 size/offset: bswap16pairs → XOR"""
    return bswap16pairs(plain_val) ^ xor_key

# ─── 解包 ───
def unpack_arc(arc_path, out_dir):
    with open(arc_path, 'rb') as f:
        data = f.read()

    count = struct.unpack_from('<I', data, 0)[0]
    print(f"文件数: {count}")

    os.makedirs(out_dir, exist_ok=True)
    names = []

    for i in range(count):
        base = 4 + i * 0x20
        entry = data[base:base+0x20]

        name = dec_name(entry[0:24])
        raw_size   = struct.unpack_from('<I', entry, 0x18)[0]
        raw_offset = struct.unpack_from('<I', entry, 0x1C)[0]

        size   = dec_u32(raw_size,   XOR_SIZE)
        offset = dec_u32(raw_offset, XOR_OFFSET)

        fdata = data[offset:offset+size]
        out_path = os.path.join(out_dir, name)
        with open(out_path, 'wb') as fout:
            fout.write(fdata)

        names.append(name)
        print(f"  [{i+1:3d}/{count}] {name:24s}  size={size:8d}  offset=0x{offset:08X}")

    # 保存文件列表 (封包时保持顺序)
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
    idx_size = 4 + count * 0x20   # header + index table

    # 第一遍: 收集文件数据,计算偏移
    files = []
    cur_offset = idx_size
    for name in names:
        fdata = open(os.path.join(in_dir, name), 'rb').read()
        files.append((name, fdata, cur_offset))
        cur_offset += len(fdata)

    # 构建输出
    out = bytearray()
    out += struct.pack('<I', count)

    for name, fdata, offset in files:
        enc_n = enc_name(name)
        enc_s = enc_u32(len(fdata), XOR_SIZE)
        enc_o = enc_u32(offset,     XOR_OFFSET)
        out += enc_n + struct.pack('<II', enc_s, enc_o)

    for name, fdata, offset in files:
        out += fdata

    os.makedirs(os.path.dirname(arc_path) or '.', exist_ok=True)
    with open(arc_path, 'wb') as f:
        f.write(out)

    print(f"封包完成: {count} 文件 → {arc_path} ({len(out):,} bytes)")

# ─── 入口 ───
if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == 'unpack':
        unpack_arc(sys.argv[2], sys.argv[3])
    elif cmd == 'pack':
        pack_arc(sys.argv[2], sys.argv[3])
    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)
