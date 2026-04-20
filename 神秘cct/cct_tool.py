#!/usr/bin/env python3
"""
cct_tool.py - Macromedia Director CCT/FGDC (Afterburner Compressed Cast) 解包工具

支持从 Director 8.x 的 .cct (Protected Cast) 文件中提取 bitmap 资源为 PNG。
格式: XFIR(LE RIFX) + FGDC + Fver/Fcdr/ABMP/FGEi 结构

用法:
    python cct_tool.py <input.cct> [output_dir]

作者: なつこ（方欣）+ Claude
参考: ScummVM Director Engine (engines/director/archive.cpp, images.cpp, cast.cpp)
"""

import struct, zlib, os, sys
import numpy as np
from PIL import Image
from collections import Counter

# ============================================================
# varint 读取 (MSB continuation bit, big-endian style)
# ============================================================
def read_varint(buf, pos):
    val = 0
    while pos < len(buf):
        b = buf[pos]
        val = (val << 7) | (b & 0x7F)
        pos += 1
        if (b & 0x80) == 0:
            return val, pos
    return val, pos

# ============================================================
# PackBits 解码 (Macintosh PackBits RLE)
# ============================================================
def decode_packbits(data, max_out):
    out = bytearray()
    pos = 0
    while pos < len(data) and len(out) < max_out:
        n = data[pos]; pos += 1
        if n < 128:     # 0-127: copy next (n+1) literal bytes
            out.extend(data[pos:pos+n+1]); pos += n+1
        elif n > 128:   # 129-255: repeat next byte (257-n) times
            if pos < len(data):
                out.extend([data[pos]] * (257-n)); pos += 1
        # n == 128: no-op
    return bytes(out)

# ============================================================
# FGDC 解析主流程
# ============================================================
def parse_fgdc(data):
    """解析 FGDC (Director Afterburner Compressed) 格式"""

    # --- 验证文件头 ---
    sig = data[:4]
    if sig != b'XFIR':
        raise ValueError(f"不是XFIR(LE RIFX)格式: {sig}")
    ftype = data[8:12]
    if ftype not in [b'CDGF', b'LPPA']:
        # CDGF = FGDC(LE), LPPA = APPL(LE)
        print(f"  警告: 类型={ftype}, 非标准FGDC/APPL")

    # --- 定位 ABMP ---
    # 跳过 Fver + Fcdr，找到 ABMP
    # Fver at offset 12
    pos = 12
    if data[pos:pos+4] != b'revF':
        raise ValueError(f"缺少Fver tag")
    pos += 4
    fver_len, pos = read_varint(data, pos)
    pos += fver_len  # 跳过Fver data

    # Fcdr
    if data[pos:pos+4] != b'rdcF':
        raise ValueError(f"缺少Fcdr tag")
    pos += 4
    fcdr_len, pos = read_varint(data, pos)
    pos += fcdr_len  # 跳过Fcdr data

    # ABMP
    if data[pos:pos+4] != b'PMBA':
        raise ValueError(f"缺少ABMP tag")
    pos += 4
    abmp_len, pos = read_varint(data, pos)
    abmp_comp_type, pos = read_varint(data, pos)
    abmp_uncomp_len, pos = read_varint(data, pos)

    # 解压ABMP
    abmp_end = pos + (abmp_len - 2)  # 大致，实际取zlib流
    abmp_dir = zlib.decompressobj().decompress(data[pos:])

    # --- 解析 ABMP 目录 ---
    # 格式: unk1(varint) + unk2(varint) + resCount(varint)
    # 每条: resId(varint) + offset(varint) + compSize(varint) + uncompSize(varint) + compType(varint) + tag(4B)
    dpos = 0
    _, dpos = read_varint(abmp_dir, dpos)
    _, dpos = read_varint(abmp_dir, dpos)
    res_count, dpos = read_varint(abmp_dir, dpos)

    entries = []
    entries_by_id = {}
    for i in range(res_count):
        resId, dpos = read_varint(abmp_dir, dpos)
        offset_raw, dpos = read_varint(abmp_dir, dpos)
        compSize, dpos = read_varint(abmp_dir, dpos)
        uncompSize, dpos = read_varint(abmp_dir, dpos)
        compType, dpos = read_varint(abmp_dir, dpos)
        tag = abmp_dir[dpos:dpos+4].decode('ascii', errors='replace')
        dpos += 4
        e = {
            'resId': resId, 'offset': offset_raw, 'compSize': compSize,
            'uncompSize': uncompSize, 'compType': compType, 'tag': tag,
            'inILS': offset_raw >= 0x7FFFFFFF
        }
        entries.append(e)
        entries_by_id[resId] = e

    # --- FGEi + ILS ---
    fgei_pos = data.find(b'IEGF')  # FGEi in LE
    if fgei_pos < 0:
        raise ValueError("缺少FGEi tag")
    p = fgei_pos + 4
    _, p = read_varint(data, p)
    fgei_body = p

    # 解压ILS (第一个zlib流)
    ils_data = zlib.decompressobj().decompress(data[fgei_body:])

    # ILS内部: varint(resId) + data[compSize] 循环
    ils_pos = 0
    ils_res = {}
    while ils_pos < len(ils_data):
        rid, ils_pos = read_varint(ils_data, ils_pos)
        if rid not in entries_by_id:
            break
        sz = entries_by_id[rid]['compSize']
        if ils_pos + sz > len(ils_data):
            break
        ils_res[rid] = ils_data[ils_pos:ils_pos+sz]
        ils_pos += sz

    # --- 获取资源数据 ---
    def get_res_data(resId):
        e = entries_by_id.get(resId)
        if not e: return b''
        if e['inILS']:
            return ils_res.get(resId, b'')
        abs_off = fgei_body + e['offset']
        try:
            return zlib.decompressobj().decompress(
                data[abs_off:abs_off + e['compSize'] + 4096])
        except:
            return b''

    return entries, entries_by_id, ils_res, get_res_data

# ============================================================
# CASt 解析 (D5+ format, BE内部)
# ============================================================
def parse_cast_bitmaps(entries, get_res_data):
    """解析所有 CASt bitmap member, 返回 {resId: {w,h,bpp,pitch,...}}"""
    bitmap_info = {}
    for e in entries:
        if e['tag'] != 'tSAC':  # CASt in LE
            continue
        cd = get_res_data(e['resId'])
        if len(cd) < 12:
            continue

        # D5+: u32BE castType + u32BE infoSize + u32BE dataSize
        ct = struct.unpack_from('>I', cd, 0)[0]
        if ct != 1:  # 1 = bitmap
            continue
        info_sz = struct.unpack_from('>I', cd, 4)[0]

        # Bitmap-specific data at offset 12 + infoSize
        bmp_off = 12 + info_sz
        if bmp_off + 24 > len(cd):
            continue

        pitch = struct.unpack_from('>H', cd, bmp_off)[0]
        top, left = struct.unpack_from('>hh', cd, bmp_off+2)
        bottom, right = struct.unpack_from('>hh', cd, bmp_off+6)
        w, h = right - left, bottom - top

        # D7+: padding(2) + editVer(2) + scroll(4) + reg(4) + flags(1) = 13 bytes
        bpp = 1
        bp = bmp_off + 10 + 13  # offset to bpp field
        if pitch & 0x8000:
            pitch &= 0x3FFF
            if bp < len(cd):
                bpp = cd[bp]

        if w > 0 and h > 0:
            bitmap_info[e['resId']] = {
                'w': w, 'h': h, 'bpp': bpp, 'pitch': pitch,
                'top': top, 'left': left
            }

    return bitmap_info

# ============================================================
# KEY* 解析 (LE格式)
# ============================================================
def parse_key_table(get_res_data, key_resId=3):
    """解析 KEY* 关联表, 返回 (cast_to_bitd, cast_to_alfa)"""
    key_data = get_res_data(key_resId)
    if len(key_data) < 12:
        return {}, {}

    # LE: u16 entrySize, u16 entrySize2, u32 total, u32 used
    es = struct.unpack_from('<H', key_data, 0)[0]
    used = struct.unpack_from('<I', key_data, 8)[0]

    cast_to_bitd = {}
    cast_to_alfa = {}
    for j in range(used):
        off = 12 + j * es
        if off + es > len(key_data):
            break
        child = struct.unpack_from('<I', key_data, off)[0]
        parent = struct.unpack_from('<I', key_data, off+4)[0]
        ktag = key_data[off+8:off+12]
        if ktag == b'DTIB':  # BITD in LE
            cast_to_bitd[parent] = child
        elif ktag == b'AFLA':  # ALFA reversed in LE
            cast_to_alfa[parent] = child

    return cast_to_bitd, cast_to_alfa

# ============================================================
# BITD 解码 → PNG
# ============================================================
def decode_bitd_to_image(bitd_data, w, h, bpp, pitch, alfa_data=None):
    """
    Director BITD 解码:
    - PackBits RLE 解压
    - 32bpp: 每行通道分离 [A*w][R*w][G*w][B*w]
    - 8bpp: 灰度/索引
    - alfa_data: 可选的独立 ALFA 通道数据 (PackBits 压缩, 8bpp per pixel)
    """
    expected = w * h * (bpp // 8)
    raw_size = pitch * h

    # 判断是否压缩
    if len(bitd_data) == raw_size or len(bitd_data) == expected:
        decoded = bitd_data  # 未压缩
    else:
        decoded = decode_packbits(bitd_data, expected)

    if len(decoded) < expected:
        decoded += b'\x00' * (expected - len(decoded))

    # 解码 ALFA 通道
    alpha_channel = None
    if alfa_data:
        alfa_expected = w * h
        if len(alfa_data) == alfa_expected:
            alpha_channel = alfa_data
        else:
            alpha_channel = decode_packbits(alfa_data, alfa_expected)
        if len(alpha_channel) < alfa_expected:
            alpha_channel += b'\x00' * (alfa_expected - len(alpha_channel))

    if bpp == 32:
        # D4+ RLE模式: 每行通道分离 [A][R][G][B], 每通道w字节
        img_r = np.zeros((h, w), dtype=np.uint8)
        img_g = np.zeros((h, w), dtype=np.uint8)
        img_b = np.zeros((h, w), dtype=np.uint8)
        img_a = np.full((h, w), 255, dtype=np.uint8)

        for y in range(h):
            row_off = y * w * 4
            a_start = row_off
            r_start = row_off + w
            g_start = row_off + 2 * w
            b_start = row_off + 3 * w
            if b_start + w <= len(decoded):
                img_a[y] = list(decoded[a_start:a_start+w])
                img_r[y] = list(decoded[r_start:r_start+w])
                img_g[y] = list(decoded[g_start:g_start+w])
                img_b[y] = list(decoded[b_start:b_start+w])

        # 如果有独立ALFA通道，优先使用
        if alpha_channel and len(alpha_channel) >= w * h:
            img_a = np.frombuffer(alpha_channel[:w*h], dtype=np.uint8).reshape(h, w)

        # 判断是否有有意义的alpha (非全0或全255)
        has_alpha = not (np.all(img_a == 255) or np.all(img_a == 0))
        if has_alpha or alpha_channel:
            return Image.merge('RGBA', (
                Image.fromarray(img_r), Image.fromarray(img_g),
                Image.fromarray(img_b), Image.fromarray(img_a)
            ))
        else:
            return Image.merge('RGB', (
                Image.fromarray(img_r), Image.fromarray(img_g),
                Image.fromarray(img_b)
            ))

        return Image.merge('RGB', (
            Image.fromarray(img_r),
            Image.fromarray(img_g),
            Image.fromarray(img_b)
        ))

    elif bpp == 16:
        arr = np.frombuffer(decoded[:w*h*2], dtype=np.uint8).reshape(h, w*2)
        pixels16 = np.frombuffer(arr.tobytes(), dtype='>u2').reshape(h, w)
        r = ((pixels16 >> 10) & 0x1F) * 255 // 31
        g = ((pixels16 >> 5) & 0x1F) * 255 // 31
        b = (pixels16 & 0x1F) * 255 // 31
        return Image.fromarray(np.stack([
            r.astype(np.uint8), g.astype(np.uint8), b.astype(np.uint8)
        ], axis=2))

    elif bpp == 8:
        arr = np.frombuffer(decoded[:pitch*h], dtype=np.uint8).reshape(h, pitch)
        return Image.fromarray(arr[:, :w], 'L')

    elif bpp == 1:
        arr = np.frombuffer(decoded[:pitch*h], dtype=np.uint8).reshape(h, pitch)
        img = np.zeros((h, w), dtype=np.uint8)
        for y in range(h):
            for x in range(w):
                byte_idx = x >> 3
                bit_idx = 7 - (x & 7)
                img[y, x] = 255 if (arr[y, byte_idx] & (1 << bit_idx)) else 0
        return Image.fromarray(img, 'L')

    return None

# ============================================================
# 主函数
# ============================================================
def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <input.cct> [output_dir]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(input_path)[0] + '_extract'

    print(f"[*] 读取: {input_path}")
    with open(input_path, 'rb') as f:
        data = f.read()
    print(f"    文件大小: {len(data):,} bytes")

    # 1. 解析FGDC容器
    print(f"[*] 解析 FGDC 容器...")
    entries, entries_by_id, ils_res, get_res_data = parse_fgdc(data)

    tag_dist = Counter(e['tag'] for e in entries)
    print(f"    资源条目: {len(entries)} ({', '.join(f'{t}×{c}' for t, c in tag_dist.most_common())})")
    print(f"    ILS 资源: {len(ils_res)}")

    # 2. 解析CASt bitmap信息
    print(f"[*] 解析 CASt bitmap 信息...")
    bitmap_info = parse_cast_bitmaps(entries, get_res_data)
    print(f"    Bitmap members: {len(bitmap_info)}")

    bpp_dist = Counter(m['bpp'] for m in bitmap_info.values())
    size_dist = Counter(f"{m['w']}x{m['h']}" for m in bitmap_info.values())
    print(f"    色深分布: {dict(bpp_dist)}")
    print(f"    常见尺寸: {dict(size_dist.most_common(5))}")

    # 3. 解析KEY*关联表
    print(f"[*] 解析 KEY* 关联表...")
    cast_to_bitd, cast_to_alfa = parse_key_table(get_res_data)
    print(f"    CASt→BITD 映射: {len(cast_to_bitd)}")
    print(f"    CASt→ALFA 映射: {len(cast_to_alfa)}")

    # 4. 批量导出
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] 导出到: {output_dir}")

    success = fail = skip = 0
    for cast_rid in sorted(bitmap_info.keys()):
        bitd_rid = cast_to_bitd.get(cast_rid)
        alfa_rid = cast_to_alfa.get(cast_rid)

        if bitd_rid is None:
            # 没有BITD — 可能是空的cast member
            fail += 1
            continue

        info = bitmap_info[cast_rid]
        w, h, bpp, pitch = info['w'], info['h'], info['bpp'], info['pitch']

        bitd = get_res_data(bitd_rid)
        if not bitd:
            fail += 1
            continue

        # 获取可选的ALFA通道数据
        alfa = get_res_data(alfa_rid) if alfa_rid else None

        try:
            img = decode_bitd_to_image(bitd, w, h, bpp, pitch, alfa)
            if img:
                fname = os.path.join(output_dir, f"cast_{cast_rid:04d}_{w}x{h}.png")
                img.save(fname)
                success += 1
            else:
                fail += 1
        except Exception as ex:
            fail += 1

    print(f"[✓] 完成: {success} 成功, {fail} 失败")

if __name__ == '__main__':
    main()
