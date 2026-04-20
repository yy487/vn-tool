#!/usr/bin/env python3
"""patch Ai5win.exe 字体缓冲区 (混合 cp932+GBK, 6189 glyphs)"""
import struct, sys, shutil
if len(sys.argv) < 2:
    print("用法: python patch_exe.py <Ai5win.exe> [output.exe]"); sys.exit(1)
src = sys.argv[1]
dst = sys.argv[2] if len(sys.argv) > 2 else src + '.patched'
if src != dst: shutil.copy2(src, dst)
data = bytearray(open(dst, 'rb').read())
OFF = 0x532C4
old = struct.unpack_from('<III', data, OFF)
struct.pack_into('<I', data, OFF, 12380)
struct.pack_into('<I', data, OFF+4, 4183764)
struct.pack_into('<I', data, OFF+8, 4183764)
open(dst, 'wb').write(data)
print(f"Patched: {dst}")
print(f"  TBL: {old[0]} -> 12380")
print(f"  FNT: {old[1]} -> 4183764")
print(f"  MSK: {old[2]} -> 4183764")
print(f"  (6189 glyphs @ 26x26)")
