#!/usr/bin/env python3
"""扫描 ARC 解包目录, 分类所有 MSK 文件为 Type A / Type B"""
import struct, sys, os

def lzss_decompress(src):
    out = bytearray(); window = bytearray(b'\x00' * 4096); wp = 0xFEE; sp = 0
    while sp < len(src):
        flags = src[sp]; sp += 1
        for bit in range(8):
            if sp >= len(src): break
            if flags & (1 << bit):
                b = src[sp]; sp += 1; out.append(b); window[wp] = b; wp = (wp + 1) & 0xFFF
            else:
                if sp + 1 >= len(src): break
                lo = src[sp]; hi = src[sp+1]; sp += 2
                off = lo | ((hi & 0xF0) << 4); ml = (hi & 0x0F) + 3
                for k in range(ml):
                    b = window[(off + k) & 0xFFF]; out.append(b); window[wp] = b; wp = (wp + 1) & 0xFFF
    return bytes(out)

def classify_msk(path):
    data = open(path, 'rb').read()
    try:
        raw = lzss_decompress(data)
    except:
        return 'ERROR', 0, 0, len(data)
    
    if len(raw) < 5:
        return 'TINY', 0, 0, len(raw)
    
    w, h = struct.unpack_from('<HH', raw, 0)
    body = raw[4:]
    
    if w > 0 and h > 0 and w <= 2048 and h <= 2048 and w * h == len(body) and max(body) <= 0x10:
        return 'A', w, h, len(raw)
    else:
        return 'B', 0, 0, len(raw)

if len(sys.argv) < 2:
    print("用法: python msk_scan.py <解包目录> [--copy 输出目录]")
    sys.exit(1)

d = sys.argv[1]
copy_dir = None
if '--copy' in sys.argv:
    idx = sys.argv.index('--copy')
    copy_dir = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else os.path.join(d, '..', 'msk_typeB')
    os.makedirs(copy_dir, exist_ok=True)
type_a, type_b, errors = [], [], []

for fn in sorted(os.listdir(d)):
    if not fn.upper().endswith('.MSK'): continue
    path = os.path.join(d, fn)
    typ, w, h, sz = classify_msk(path)
    if typ == 'A':
        type_a.append((fn, w, h, sz))
    elif typ == 'B':
        type_b.append((fn, sz))
    else:
        errors.append((fn, typ, sz))

print(f"=== Type A (立绘遮罩, 0x00-0x10, 有头) === [{len(type_a)}个]")
for fn, w, h, sz in type_a:
    print(f"  {fn}: {w}×{h}")

print(f"\n=== Type B (alpha遮罩, 0x00-0xFF, 无头) === [{len(type_b)}个]")
for fn, sz in type_b:
    print(f"  {fn}: {sz}B")

if copy_dir and type_b:
    import shutil
    for fn, sz in type_b:
        shutil.copy2(os.path.join(d, fn), os.path.join(copy_dir, fn))
    print(f"\n→ {len(type_b)} 个 Type B 文件已复制到: {copy_dir}")

if errors:
    print(f"\n=== 异常 === [{len(errors)}个]")
    for fn, typ, sz in errors:
        print(f"  {fn}: {typ} {sz}B")
