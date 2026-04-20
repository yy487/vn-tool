#!/usr/bin/env python3
"""AI5WIN v3 字体生成器 (あしたの雪之丞2)

从 TTF 字体 + charset.json 生成混合 cp932+GBK 的 FONT00.TBL/FNT/MSK

用法:
  python font_gen.py <charset.json> <font.ttf> <原版FONT00目录> <输出目录> [选项]

参数:
  charset.json     scan_chars.py 生成的字符集文件
  font.ttf         中文 TTF 字体文件
  原版FONT00目录   包含原版 FONT00.TBL/FNT/MSK (LZSS 压缩) 的目录
  输出目录         输出 FONT00.TBL/FNT/MSK + patch_exe.py + encoding_map.json

选项:
  --size N         字号 (默认 22)
  --glyph WxH     字形尺寸 (默认 26x26)
  --no-compress    不压缩 (调试用, 引擎可能不认)

示例:
  python font_gen.py charset.json alyce_humming.ttf orig_font/ output/
  python font_gen.py charset.json msyh.ttc orig_font/ output/ --size 20
"""
import struct, sys, os, json, subprocess

# ══════════════════════════════════════════════
# LZSS
# ══════════════════════════════════════════════

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

def lzss_compress_py(data):
    """纯 Python LZSS 压缩 (慢但正确, 禁用 overlap)"""
    WINDOW = 4096; MASK = 0xFFF; MAX_M = 18; MIN_M = 3; INIT = 0xFEE
    window = bytearray(b'\x00' * WINDOW)
    wp = INIT; sp = 0; n = len(data); out = bytearray()
    while sp < n:
        fp = len(out); out.append(0); flags = 0
        for bit in range(8):
            if sp >= n: break
            best_len = 0; best_off = 0
            for back in range(1, WINDOW):
                off = (wp - back) & MASK
                ml = min(MAX_M, back)
                k = 0
                while k < ml and sp + k < n and window[(off + k) & MASK] == data[sp + k]:
                    k += 1
                if k > best_len:
                    best_len = k; best_off = off
                    if k == MAX_M: break
            if best_len >= MIN_M:
                out.append(best_off & 0xFF)
                out.append(((best_off >> 4) & 0xF0) | ((best_len - MIN_M) & 0x0F))
                for _ in range(best_len):
                    window[wp] = data[sp]; wp = (wp + 1) & MASK; sp += 1
            else:
                flags |= (1 << bit)
                out.append(data[sp]); window[wp] = data[sp]; wp = (wp + 1) & MASK; sp += 1
        out[fp] = flags
    return bytes(out)

def lzss_compress(data, c_compressor=None):
    """LZSS 压缩, 优先用 C 编译的版本"""
    if c_compressor and os.path.exists(c_compressor):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.raw') as f:
            f.write(data); tmp_in = f.name
        tmp_out = tmp_in + '.lzss'
        try:
            r = subprocess.run([c_compressor, tmp_in, tmp_out], capture_output=True, timeout=300)
            if r.returncode == 0 and os.path.exists(tmp_out):
                return open(tmp_out, 'rb').read()
        except:
            pass
        finally:
            for f in [tmp_in, tmp_out]:
                if os.path.exists(f): os.remove(f)
    print("    (使用 Python 压缩, 较慢...)")
    return lzss_compress_py(data)

# ══════════════════════════════════════════════
# 字体生成
# ══════════════════════════════════════════════

def generate_font(charset_path, ttf_path, orig_dir, out_dir,
                  font_size=22, glyph_w=26, glyph_h=26, do_compress=True):
    from PIL import ImageFont, Image, ImageDraw

    os.makedirs(out_dir, exist_ok=True)
    GS = glyph_w * glyph_h

    # ── 1. 加载原版字体 ──
    print("[1/7] 加载原版 FONT00...")
    orig_tbl = lzss_decompress(open(os.path.join(orig_dir, 'FONT00.TBL'), 'rb').read())
    orig_fnt = lzss_decompress(open(os.path.join(orig_dir, 'FONT00.FNT'), 'rb').read())
    orig_msk = lzss_decompress(open(os.path.join(orig_dir, 'FONT00.MSK'), 'rb').read())
    orig_count = struct.unpack_from('<H', orig_tbl, 0)[0]
    print(f"  原版: {orig_count} 个 cp932 字形")

    # 解析原版条目
    cp932_entries = {}
    for i in range(orig_count):
        code = struct.unpack_from('<H', orig_tbl, 2 + i * 2)[0]
        fnt = orig_fnt[i * GS:(i + 1) * GS]
        msk = orig_msk[i * GS:(i + 1) * GS]
        lo, hi = code & 0xFF, (code >> 8) & 0xFF
        try:
            ch = bytes([lo, hi]).decode('cp932') if lo >= 0x80 else chr(lo)
        except:
            ch = None
        cp932_entries[code] = (ch, fnt, msk)

    # ── 2. 加载字符集 ──
    print("[2/7] 加载字符集...")
    charset = json.load(open(charset_path, 'r', encoding='utf-8'))
    chars = charset['chars']
    print(f"  字符集: {len(chars)} 个字符")

    # ── 3. 编码映射 ──
    print("[3/7] 构建编码映射...")
    SPECIAL_MAP = {}
    pua_next = 0xFE50

    gbk_chars = []  # (unicode_char, gbk_code)
    for c in chars:
        if c == '\ufffd':
            continue

        # 尝试 GBK 编码
        try:
            b = c.encode('gbk')
        except:
            # GBK 编码失败 → 分配 PUA
            pua_code = pua_next
            pua_next += 1
            SPECIAL_MAP[c] = struct.pack('>H', pua_code)
            gbk_chars.append((c, pua_code))
            continue

        if len(b) == 2:
            code = b[0] | (b[1] << 8)
        elif len(b) == 1:
            code = b[0]
        else:
            continue
        gbk_chars.append((c, code))

    # ── 4. 合并, 处理冲突 ──
    print("[4/7] 合并 cp932 + GBK (处理冲突)...")
    final_entries = []
    used_codes = set()

    # 4a. 所有原始 cp932 条目
    for code, (ch, fnt, msk) in cp932_entries.items():
        final_entries.append((code, ch, fnt, msk))
        used_codes.add(code)

    # 4b. GBK 新字形
    font = ImageFont.truetype(ttf_path, font_size)
    added = 0
    conflict_count = 0

    for c, code in gbk_chars:
        if code in used_codes:
            orig_ch = cp932_entries.get(code, (None,))[0]
            if orig_ch == c:
                continue  # 同一字符, 已有
            # 冲突 → PUA
            new_code = pua_next
            pua_next += 1
            SPECIAL_MAP[c] = struct.pack('>H', new_code)
            code = new_code
            conflict_count += 1

        # 渲染字形
        img = Image.new('L', (glyph_w, glyph_h), 0)
        draw = ImageDraw.Draw(img)
        bbox = font.getbbox(c)
        cw = bbox[2] - bbox[0]
        ch_h = bbox[3] - bbox[1]
        x = (glyph_w - cw) // 2 - bbox[0]
        y = (glyph_h - ch_h) // 2 - bbox[1]
        draw.text((x, y), c, fill=255, font=font)
        raw = img.tobytes()

        fnt = bytes(raw)
        msk = bytes(min(p >> 4, 0x10) for p in raw)

        final_entries.append((code, c, fnt, msk))
        used_codes.add(code)
        added += 1

    n = len(final_entries)
    print(f"  cp932: {orig_count}, GBK新增: {added}, 冲突PUA: {conflict_count}")
    print(f"  总计: {n} 个字形")

    # ── 5. 生成二进制数据 ──
    print("[5/7] 生成 TBL/FNT/MSK...")
    tbl_data = struct.pack('<H', n)
    fnt_data = bytearray()
    msk_data = bytearray()
    for code, ch, fnt, msk in final_entries:
        tbl_data += struct.pack('<H', code)
        fnt_data += fnt
        msk_data += msk

    tbl_sz = len(tbl_data)
    fnt_sz = len(fnt_data)
    msk_sz = len(msk_data)
    print(f"  TBL: {tbl_sz} B, FNT: {fnt_sz} B ({fnt_sz/1024/1024:.1f}MB), MSK: {msk_sz} B")

    # ── 6. LZSS 压缩 ──
    if do_compress:
        print("[6/7] LZSS 压缩...")
        # 找 C 编译的压缩器
        c_comp = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lzss_comp')
        if not os.path.exists(c_comp):
            c_comp = None

        for name, raw_data in [('FONT00.TBL', tbl_data), ('FONT00.FNT', bytes(fnt_data)), ('FONT00.MSK', bytes(msk_data))]:
            comp = lzss_compress(raw_data, c_comp)
            # 验证
            dec = lzss_decompress(comp)
            if dec != raw_data:
                print(f"  ✗ {name} 压缩验证失败!")
                sys.exit(1)
            ratio = len(comp) * 100 // len(raw_data)
            open(os.path.join(out_dir, name), 'wb').write(comp)
            print(f"  {name}: {len(raw_data)} → {len(comp)} ({ratio}%) ✓")
    else:
        print("[6/7] 跳过压缩 (--no-compress)")
        open(os.path.join(out_dir, 'FONT00.TBL'), 'wb').write(tbl_data)
        open(os.path.join(out_dir, 'FONT00.FNT'), 'wb').write(bytes(fnt_data))
        open(os.path.join(out_dir, 'FONT00.MSK'), 'wb').write(bytes(msk_data))

    # ── 7. 辅助文件 ──
    print("[7/7] 生成辅助文件...")

    # patch_exe.py
    patch_code = f'''#!/usr/bin/env python3
"""patch Ai5win.exe 字体缓冲区 ({n} glyphs)"""
import struct, sys, shutil
if len(sys.argv) < 2:
    print("用法: python patch_exe.py <Ai5win.exe> [output.exe]"); sys.exit(1)
src = sys.argv[1]
dst = sys.argv[2] if len(sys.argv) > 2 else src + '.patched'
if src != dst: shutil.copy2(src, dst)
data = bytearray(open(dst, 'rb').read())
OFF = 0x532C4
old = struct.unpack_from('<III', data, OFF)
struct.pack_into('<I', data, OFF, {tbl_sz})
struct.pack_into('<I', data, OFF+4, {fnt_sz})
struct.pack_into('<I', data, OFF+8, {msk_sz})
open(dst, 'wb').write(data)
print(f"Patched: {{dst}}")
print(f"  TBL: {{old[0]}} → {tbl_sz}")
print(f"  FNT: {{old[1]}} → {fnt_sz}")
print(f"  MSK: {{old[2]}} → {msk_sz}")
print(f"  ({n} glyphs @ {glyph_w}x{glyph_h})")
'''
    open(os.path.join(out_dir, 'patch_exe.py'), 'w').write(patch_code)

    # encoding_map.json (给 inject 工具用的 SPECIAL_CHAR_MAP)
    special_json = {
        "total_glyphs": n,
        "cp932_count": orig_count,
        "gbk_count": added,
        "conflict_pua": conflict_count,
        "glyph_size": f"{glyph_w}x{glyph_h}",
        "font": os.path.basename(ttf_path),
        "font_size": font_size,
        "special_chars": {},
    }
    for c, bs in SPECIAL_MAP.items():
        special_json["special_chars"][c] = f"0x{bs.hex().upper()}"
    json.dump(special_json, open(os.path.join(out_dir, 'encoding_map.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=2)

    # inject 用的 SPECIAL_CHAR_MAP 代码片段
    if SPECIAL_MAP:
        lines = ["# 复制到 ai5win_mes_inject.py 的 SPECIAL_CHAR_MAP", "SPECIAL_CHAR_MAP = {"]
        for c, bs in SPECIAL_MAP.items():
            lines.append(f"    '{c}': b'\\x{bs[0]:02X}\\x{bs[1]:02X}',")
        lines.append("}")
        snippet = '\n'.join(lines)
        open(os.path.join(out_dir, 'SPECIAL_CHAR_MAP.txt'), 'w', encoding='utf-8').write(snippet)
        print(f"  SPECIAL_CHAR_MAP: {len(SPECIAL_MAP)} 个映射 → SPECIAL_CHAR_MAP.txt")

    # 预览图
    try:
        cols = 50
        preview_n = min(500, n)
        rows = (preview_n + cols - 1) // cols
        margin = 2
        preview = Image.new('RGBA', (cols * (glyph_w + margin), rows * (glyph_h + margin)), (30, 30, 30, 255))
        for i in range(preview_n):
            gx = (i % cols) * (glyph_w + margin)
            gy = (i // cols) * (glyph_h + margin)
            off = i * GS
            for y in range(glyph_h):
                for x in range(glyph_w):
                    v = fnt_data[off + y * glyph_w + x]
                    if v > 0:
                        preview.putpixel((gx + x, gy + y), (255, 255, 255, v))
        preview.save(os.path.join(out_dir, 'preview.png'))
        print(f"  预览图: preview.png")
    except:
        pass

    print(f"\n{'='*50}")
    print(f"完成! {n} 个字形 ({orig_count} cp932 + {added} GBK)")
    print(f"输出目录: {out_dir}/")
    print(f"  FONT00.TBL / FONT00.FNT / FONT00.MSK")
    print(f"  patch_exe.py")
    print(f"  encoding_map.json")
    if SPECIAL_MAP:
        print(f"  SPECIAL_CHAR_MAP.txt (复制到 inject 工具)")
    print(f"\n下一步:")
    print(f"  1. python {out_dir}/patch_exe.py Ai5win.exe")
    print(f"  2. 把 FONT00.* 替换进 data.arc")
    print(f"  3. 把 SPECIAL_CHAR_MAP.txt 里的内容复制到 ai5win_mes_inject.py")


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)

    charset_path = sys.argv[1]
    ttf_path = sys.argv[2]
    orig_dir = sys.argv[3]
    out_dir = sys.argv[4]

    font_size = 22
    glyph_w, glyph_h = 26, 26
    do_compress = True

    i = 5
    while i < len(sys.argv):
        if sys.argv[i] == '--size':
            font_size = int(sys.argv[i + 1]); i += 2
        elif sys.argv[i] == '--glyph':
            w, h = sys.argv[i + 1].split('x')
            glyph_w, glyph_h = int(w), int(h); i += 2
        elif sys.argv[i] == '--no-compress':
            do_compress = False; i += 1
        else:
            print(f"未知选项: {sys.argv[i]}"); sys.exit(1)

    generate_font(charset_path, ttf_path, orig_dir, out_dir,
                  font_size, glyph_w, glyph_h, do_compress)


if __name__ == '__main__':
    main()
