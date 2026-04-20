#!/usr/bin/env python3
"""
FPK 引擎封包工具 (TBitchX / 自研引擎)

文件结构:
  Header (0x1C):
    [00] "FPK\0"            (4B)
    [04] "0100"              (4B)
    [08] header_size = 0x1C  (u32)
    [0C] file_count          (u32)
    [10] reserved = 0        (u32)
    [14] section_name        (8B, e.g. "ScrBin\0\0")
  Index (file_count × 24B):
    [00] name     (12B, \0 填充)
    [0C] flag     (u32, bit0=1 则加密)
    [10] offset   (u32, 绝对)
    [14] size     (u32)
  Data:
    各文件原始数据; flag&1 时末尾有 8B 尾部 (orig_size + padding 使对齐到 4B)

加密算法 (FUN_0044d340, 从末尾向前 u32 一组):
  key 初始: iVar2 = -0x6b3a9f8b
  用文件名每字符 c 迭代 (最多12): iVar2 = (c - (c + 0x6b3a9f8b) * iVar2) + 0x2d13
  加密流 (封包):
    padded_size = (orig_size + 3) & ~3
    buf = data + pad_to_4 + u32(orig_size) + u32(0)  # 末尾 8B, 共 padded+8
    然后从**末尾**向前按 u32 处理:
      cipher = (plain ^ key) + running
      running -= 3
      key = (key - cipher) >> 7 ^ (key + running_before) << 7   (uint32)
    等等 - 反推解密方程得加密.
  解密 (从前向后扫 buf, 每次取 u32):
    plain = (cipher - running) ^ key
    *p = plain
    key = (key - plain) >> 7 ^ (key + running) << 7
    running -= 3
    (running 初值 = size - 4 + key0, key 初值 = key0)
"""

import os, sys, struct

U32 = 0xFFFFFFFF

def find_key(enc_data: bytes):
    """参考 GARbro FpkOpener.FindKey:
    对加密文件末尾 8B 做反推, 暴力扫 key (32位), 验证加密长度==((orig+3)&~3)+8.
    实际 GARbro 用 KnownKeys 列表, 这里我们直接扫全部 uint 是不可行的,
    但公式可以变形: 给定 test_length==len(enc_data), 解出 key.
    
    公式(GARbro):
      k1 = key + size - 4
      k2 = ((key - ((t1 - k1) ^ key)) >> 7) ^ ((k1 + key) << 7)
      test_length = ((((t0 - (k1 - 3)) ^ k2) + 3) & ~3) + 8
    其中 t0 = *(size-8), t1 = *(size-4).
    
    无法闭式反解, 但试验表明每作品 key 固定. 我们在已知少量候选里搜.
    这里采用策略: 对同一 FPK 里所有加密条目求公共 key (逐一暴力, 32位扫不现实,
    退化到 GARbro 风格 — 维护 KnownKeys). 若无匹配, 由用户提供."""
    pass

def find_key_bruteforce(enc_data: bytes, progress=False):
    """32 位全扫描 key (实际跑也就 1-2 分钟).
    验证: ((orig+3)&~3)+8 == size 且 orig>0 且 orig<size-4.
    """
    size = len(enc_data)
    if size < 8: return None
    t0 = struct.unpack_from('<I', enc_data, size - 8)[0]
    t1 = struct.unpack_from('<I', enc_data, size - 4)[0]

    # 先试 KNOWN_KEYS
    for key in KNOWN_KEYS:
        k1 = (key + size - 4) & U32
        tmp = (t1 - k1) & U32
        v1 = (tmp ^ key) & U32  # = 第一步写入的值
        k2_new = ((((key - v1) & U32) >> 7) ^ (((k1 + key) & U32) << 7)) & U32
        k1_new = (k1 - 3) & U32
        orig = (((t0 - k1_new) & U32) ^ k2_new) & U32
        if ((orig + 3) & ~3) + 8 == size and 0 < orig < size - 4:
            return key, orig

    # 32 位扫描 (仅作最后手段)
    import time
    t_start = time.time()
    for key in range(1 << 32):
        if progress and (key & 0xFFFFFF) == 0:
            print(f"  scan 0x{key:08x}... ({time.time()-t_start:.1f}s)")
        k1 = (key + size - 4) & U32
        v1 = (((t1 - k1) & U32) ^ key) & U32
        k2_new = ((((key - v1) & U32) >> 7) ^ (((k1 + key) & U32) << 7)) & U32
        k1_new = (k1 - 3) & U32
        orig = (((t0 - k1_new) & U32) ^ k2_new) & U32
        if ((orig + 3) & ~3) + 8 == size and 0 < orig < size - 4:
            return key, orig
    return None

# 已知 key 列表
# 0x18249191: TBitchX (来自 FUN_00453540 返回的常量, 游戏 scrbin.fpk 等)
KNOWN_KEYS = [0x18249191, 0]

def _transform(buf: bytearray, key0: int):
    """GARbro Decrypt 的精确移植:
      dptr 从 length/4-1 递减到 0:
        *dptr = (*dptr - k1) ^ k2
        k2 = ((k2 - *dptr) >> 7) ^ ((k1 + k2) << 7)
        k1 -= 3
      k1 初始 = key + len - 4, k2 初始 = key.
    """
    n = len(buf)
    assert n % 4 == 0
    k1 = (key0 + n - 4) & U32
    k2 = key0 & U32
    for off in range(n - 4, -1, -4):
        v = struct.unpack_from('<I', buf, off)[0]
        v = (((v - k1) & U32) ^ k2) & U32
        struct.pack_into('<I', buf, off, v)
        k2 = ((((k2 - v) & U32) >> 7) ^ (((k1 + k2) & U32) << 7)) & U32
        k1 = (k1 - 3) & U32

def decrypt(buf: bytearray, key0: int):
    _transform(buf, key0)
    n = len(buf)
    orig_size = struct.unpack_from('<I', buf, n - 8)[0]
    return orig_size

def encrypt(data: bytes, key0: int, trailing: int = 0) -> bytes:
    """反向: out[off] 已知(明文), 求 in[off]. 解 v_out = (v_in - k1) ^ k2.
    => v_in = (v_out ^ k2) + k1. 但 k2 更新用 v_out (写回后的值), 顺序一致.
    trailing: 末尾 u32 的值 (保持原 FPK bit-perfect 用)
    """
    orig = len(data)
    padded = (orig + 3) & ~3
    buf = bytearray(data) + bytes(padded - orig) + struct.pack('<II', orig, trailing)
    n = len(buf)
    k1 = (key0 + n - 4) & U32
    k2 = key0 & U32
    for off in range(n - 4, -1, -4):
        v_out = struct.unpack_from('<I', buf, off)[0]
        v_in = ((v_out ^ k2) + k1) & U32
        struct.pack_into('<I', buf, off, v_in)
        k2 = ((((k2 - v_out) & U32) >> 7) ^ (((k1 + k2) & U32) << 7)) & U32
        k1 = (k1 - 3) & U32
    return bytes(buf)


def unpack_fbx(data: bytes) -> bytes:
    """GARbro UnpackFbx 移植: FBX\\x01 压缩格式 (2-bit 控制流变种 LZSS).
    header:
      [00] 'FBX\\x01'
      [07] data_start (通常 0x10)
      [08] packed_size (u32)
      [0C] unpacked_size (u32)
    压缩流从 data[header[7]] 开始, packed_size 字节.
    """
    assert data[:4] == b'FBX\x01'
    data_start = data[7]
    packed_size = struct.unpack_from('<I', data, 8)[0]
    unpacked_size = struct.unpack_from('<I', data, 0xC)[0]
    src = data[data_start:data_start + packed_size]
    sp = 0
    output = bytearray(unpacked_size)
    dst = 0
    ctl = 1
    out_len = unpacked_size

    def rd():
        nonlocal sp
        if sp >= len(src): return -1
        b = src[sp]; sp += 1
        return b

    while dst < out_len:
        if ctl == 1:
            c = rd()
            if c < 0: break
            ctl = c | 0x100
        mode = ctl & 3
        if mode == 0:
            b = rd()
            if b < 0: break
            output[dst] = b; dst += 1
        elif mode == 1:
            count = rd()
            if count < 0: break
            count = min(count + 2, out_len - dst)
            for _ in range(count):
                b = rd()
                if b < 0: break
                output[dst] = b; dst += 1
        elif mode == 2:
            hi = rd(); lo = rd()
            if lo < 0: break
            offset = (hi << 8) | lo
            count = min((offset & 0x1F) + 4, out_len - dst)
            offset >>= 5
            # CopyOverlapped: src from (dst - offset - 1), 长度 count, 逐字节(支持重叠)
            base = dst - offset - 1
            for i in range(count):
                output[dst + i] = output[base + i]
            dst += count
        else:  # mode == 3
            exctl = rd()
            if exctl < 0: break
            count = exctl & 0x3F
            sub = exctl >> 6
            if sub == 0:
                lo = rd()
                if lo < 0: break
                count = (count << 8) | lo
                count = min(count + 0x102, out_len - dst)
                for _ in range(count):
                    b = rd()
                    if b < 0: break
                    output[dst] = b; dst += 1
            elif sub == 1:
                hi = rd(); lo = rd()
                if lo < 0: break
                offset = (hi << 8) | lo
                count = (count << 5) | (offset & 0x1F)
                count = min(count + 0x24, out_len - dst)
                offset >>= 5
                base = dst - offset - 1
                for i in range(count):
                    output[dst + i] = output[base + i]
                dst += count
            elif sub == 3:
                # skip `count` bytes, reset ctl
                sp += count
                ctl = 1 << 2
            # sub == 2: GARbro falls through (no-op)
        ctl >>= 2
    return bytes(output)


def _cli_unpack_fbx(in_path, out_path):
    data = open(in_path, 'rb').read()
    out = unpack_fbx(data)
    open(out_path, 'wb').write(out)
    print(f"unpacked FBX: {len(data)} -> {len(out)}  ({out_path})")


def unpack(fpk_path, out_dir, decompress_fbx=True):
    with open(fpk_path, 'rb') as f:
        data = f.read()
    assert data[:4] == b'FPK\0' and data[4:8] == b'0100'
    header_size, count, _res = struct.unpack_from('<III', data, 8)
    section = data[0x14:header_size].rstrip(b'\0').decode('ascii', 'replace')
    print(f"FPK: section={section!r} count={count} header=0x{header_size:x}")

    # 收集条目, 找出第一个 flag=1 且 size>8 的用来反推 key
    entries = []
    for i in range(count):
        p = header_size + i * 24
        flag, offset, size = struct.unpack_from('<III', data, p)
        name_raw = data[p+12:p+24]
        nul = name_raw.find(b'\0')
        name = name_raw if nul < 0 else name_raw[:nul]
        entries.append((name, flag, offset, size))

    key = None
    for name, flag, offset, size in entries:
        if flag & 1 and size > 8:
            print(f"searching key via {name.decode('latin1')} (size={size})...")
            enc = data[offset:offset+size]
            result = find_key_bruteforce(enc)
            if result:
                key, orig = result
                print(f"  found key = 0x{key:08x} (orig_size={orig})")
                break
    if key is None:
        print("!! no key found in small range, you need to extend brute force or provide key")
        return

    os.makedirs(out_dir, exist_ok=True)
    trailers = {}  # name -> trailing u32 (解密后末尾 4 字节的值, 封包时需保留以求 bit-perfect)
    for name, flag, offset, size in entries:
        blob = bytearray(data[offset:offset+size])
        if flag & 1:
            orig = decrypt(blob, key)
            # 保存解密后末尾 u32 (位于 size-4)
            trailers[name.decode('ascii', 'replace')] = struct.unpack_from('<I', blob, size - 4)[0]
            blob = blob[:orig]
            tag = 'ENC'
        else:
            tag = '   '
        print(f"  [{tag}] {name.decode('latin1'):14s}  off=0x{offset:08x} size={size:8d} -> {len(blob)}")
        out_name = name.decode('ascii', 'replace')
        # 如开启 decompress_fbx 且数据以 FBX\x01 开头, 自动内层解压
        if decompress_fbx and len(blob) >= 4 and blob[:4] == b'FBX\x01':
            try:
                blob = unpack_fbx(bytes(blob))
                tag = tag.strip() + '+FBX'
            except Exception as e:
                print(f"    [warn] FBX decompress failed for {out_name}: {e}")
        with open(os.path.join(out_dir, out_name), 'wb') as g:
            g.write(blob)
    # 保存元数据
    with open(os.path.join(out_dir, '_fpk_meta.txt'), 'w') as g:
        g.write(f"section={section}\n")
        g.write(f"key=0x{key:08x}\n")
        for name, flag, _o, _s in entries:
            n = name.decode('ascii','replace')
            tr = trailers.get(n, 0)
            g.write(f"{n}\t{flag}\t{tr:08x}\n")
    print(f"-> {out_dir}/  (key=0x{key:08x})")


def pack(in_dir, fpk_path):
    meta_path = os.path.join(in_dir, '_fpk_meta.txt')
    with open(meta_path) as f:
        lines = f.read().splitlines()
    section = lines[0].split('=', 1)[1]
    key = int(lines[1].split('=', 1)[1], 16) if lines[1].startswith('key=') else 0
    entries = []
    for line in lines[2:]:
        if not line.strip(): continue
        parts = line.split('\t')
        name = parts[0]
        flag = int(parts[1])
        trailing = int(parts[2], 16) if len(parts) > 2 else 0
        entries.append((name, flag, trailing))
    count = len(entries)
    header_size = 0x1C
    index_size = count * 24
    data_start = header_size + index_size
    blobs = []
    cur = data_start
    index_bytes = bytearray()
    for name, flag, trailing in entries:
        raw = open(os.path.join(in_dir, name), 'rb').read()
        if flag & 1:
            blob = encrypt(raw, key, trailing)
        else:
            blob = raw
        blobs.append(blob)
        name_field = name.encode('ascii').ljust(12, b'\0')[:12]
        index_bytes += struct.pack('<III', flag, cur, len(blob)) + name_field
        cur += len(blob)
    sec_field = section.encode('ascii').ljust(8, b'\0')[:8]
    header = b'FPK\0' + b'0100' + struct.pack('<III', header_size, count, 0) + sec_field
    with open(fpk_path, 'wb') as f:
        f.write(header)
        f.write(index_bytes)
        for b in blobs:
            f.write(b)
    print(f"packed {count} files (key=0x{key:08x}) -> {fpk_path}")


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("usage:\n"
              "  fpk_tool.py unpack <in.fpk> <out_dir> [--raw]   # 解包 FPK (默认自动解 FBX 内层压缩)\n"
              "  fpk_tool.py pack <in_dir> <out.fpk>             # 回封 FPK (需用 --raw 解的原始压缩文件)\n"
              "  fpk_tool.py unfbx <in.fbx> <out.bin>            # 仅解压 FBX\\x01 内层压缩\n"
              "\n"
              "注: pack 当前只支持原始加密域的回封 (即 --raw 解出的 FBX\\x01 压缩文件).\n"
              "    要修改脚本内容需另外实现 FBX\\x01 的压缩器 (尚未实现).")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'unpack':
        # 默认自动解 FBX\x01; --raw 参数保留压缩态
        args = [a for a in sys.argv[2:] if not a.startswith('--')]
        raw = '--raw' in sys.argv
        unpack(args[0], args[1], decompress_fbx=not raw)
    elif cmd == 'pack':
        pack(sys.argv[2], sys.argv[3])
    elif cmd == 'unfbx':
        _cli_unpack_fbx(sys.argv[2], sys.argv[3])
