#!/usr/bin/env python3
"""
AI5WIN v2 Mes.Arc 解包/封包工具 (不做LZSS处理)

ARC中存储的就是LZSS压缩后的原始数据, 本工具只做索引解密和数据分割/拼接。
LZSS解压/压缩由 lime_extract / lime_inject 负责。

条目 0x1C字节: name(20B)^0x03 + size(4B)^0x33656755 + offset(4B)^0x37947233

用法:
  python lime_arc.py unpack <input.arc> [output_dir]
  python lime_arc.py pack   <input_dir>  [output.arc]
"""
import struct, sys, os

NAME_KEY = 0x03
SIZE_KEY = 0x33656755
OFF_KEY  = 0x37947233
ENTRY_SZ = 0x1C
NAME_LEN = 20

def unpack(arc_path, out_dir):
    data = open(arc_path, 'rb').read()
    fc = struct.unpack_from('<I', data, 0)[0]
    os.makedirs(out_dir, exist_ok=True)
    # 保存原始顺序
    with open(os.path.join(out_dir, '_index.txt'), 'w') as idx:
        for i in range(fc):
            base = 4 + i * ENTRY_SZ
            name = bytes(b ^ NAME_KEY for b in data[base:base+NAME_LEN]).split(b'\x00')[0].decode('ascii')
            size = struct.unpack_from('<I', data, base+0x14)[0] ^ SIZE_KEY
            offset = struct.unpack_from('<I', data, base+0x18)[0] ^ OFF_KEY
            with open(os.path.join(out_dir, name), 'wb') as f:
                f.write(data[offset:offset+size])
            idx.write(name + '\n')
    print(f"[INFO] 解包 {fc} 个文件 -> {out_dir}")

def pack(in_dir, arc_path):
    idx_path = os.path.join(in_dir, '_index.txt')
    names = []
    if os.path.exists(idx_path):
        names = [l.strip() for l in open(idx_path) if l.strip()]
    if not names:  # 空文件或不存在都fallback
        names = sorted(f for f in os.listdir(in_dir) if not f.startswith('_'))
        print("  [WARN] _index.txt 为空或不存在, 使用目录扫描(字母序)")
    fc = len(names)
    data_start = 4 + fc * ENTRY_SZ
    with open(arc_path, 'wb') as f:
        f.write(struct.pack('<I', fc))
        # 先占位索引表
        f.write(b'\x00' * (fc * ENTRY_SZ))
        # 写数据, 记录offset和size
        entries = []
        for name in names:
            fdata = open(os.path.join(in_dir, name), 'rb').read()
            offset = f.tell()
            f.write(fdata)
            entries.append((name, len(fdata), offset))
        # 回填索引表
        f.seek(4)
        for name, size, offset in entries:
            buf = bytearray(ENTRY_SZ)
            nb = name.encode('ascii').ljust(NAME_LEN, b'\x00')
            for j in range(NAME_LEN):
                buf[j] = nb[j] ^ NAME_KEY
            struct.pack_into('<I', buf, 0x14, size ^ SIZE_KEY)
            struct.pack_into('<I', buf, 0x18, offset ^ OFF_KEY)
            f.write(buf)
    print(f"[INFO] 封包 {fc} 个文件 -> {arc_path}")

def main():
    if len(sys.argv) < 3:
        print(f"用法:\n  python {sys.argv[0]} unpack <input.arc> [output_dir]")
        print(f"  python {sys.argv[0]} pack   <input_dir>  [output.arc]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'unpack':
        arc = sys.argv[2]
        out = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(arc)[0]
        unpack(arc, out)
    elif cmd == 'pack':
        d = sys.argv[2]
        arc = sys.argv[3] if len(sys.argv) > 3 else d.rstrip('/\\') + '.arc'
        pack(d, arc)

if __name__ == '__main__':
    main()
