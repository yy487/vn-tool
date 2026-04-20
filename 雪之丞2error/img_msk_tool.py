#!/usr/bin/env python3
"""AI5WIN 图片 MSK 工具 (あしたの雪之丞2)

MSK = LZSS 压缩的 alpha 通道 (0x00=透明, 0xFF=不透明, 中间值=抗锯齿)
尺寸与对应 G24 图片一致，无文件头。

用法:
  解包 (MSK → PNG alpha):
    python img_msk_tool.py decode <input.MSK> <ref.G24 or ref.png> [output.png]
    python img_msk_tool.py decode <msk_dir> <g24_dir> [png_dir]

  合成 (G24 + MSK → RGBA PNG):
    python img_msk_tool.py merge <input.G24> <input.MSK> [output.png]

  封包 (PNG alpha → MSK):
    python img_msk_tool.py encode <input.png> [output.MSK]
    python img_msk_tool.py encode <png_dir> [msk_dir]

  从 RGBA PNG 提取 alpha → MSK:
    python img_msk_tool.py extract_alpha <input_rgba.png> [output.MSK]
"""
import struct, sys, os, subprocess

# ── LZSS ──
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
                lo = src[sp]; hi = src[sp + 1]; sp += 2
                off = lo | ((hi & 0xF0) << 4); ml = (hi & 0x0F) + 3
                for k in range(ml):
                    b = window[(off + k) & 0xFFF]; out.append(b); window[wp] = b; wp = (wp + 1) & 0xFFF
    return bytes(out)

def lzss_compress(data):
    """LZSS 压缩 (无 overlap, 保证正确性)"""
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
                ml = min(MAX_M, back)  # no overlap
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

def _try_c_compress(data):
    """尝试用 C 编译的快速压缩器"""
    c_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lzss_comp')
    if not os.path.exists(c_path):
        return None
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.raw') as f:
        f.write(data); tmp_in = f.name
    tmp_out = tmp_in + '.lzss'
    try:
        r = subprocess.run([c_path, tmp_in, tmp_out], capture_output=True, timeout=120)
        if r.returncode == 0 and os.path.exists(tmp_out):
            result = open(tmp_out, 'rb').read()
            return result
    except:
        pass
    finally:
        for f in [tmp_in, tmp_out]:
            if os.path.exists(f): os.remove(f)
    return None

def compress(data):
    """LZSS 压缩, 优先用 C 版本"""
    result = _try_c_compress(data)
    if result is not None:
        return result
    return lzss_compress(data)

# ── G24 解码 ──
def g24_get_size(path):
    """从 G24 文件读取宽高"""
    with open(path, 'rb') as f:
        header = f.read(8)
    x, y, w, h = struct.unpack_from('<hhhh', header, 0)
    return w, h

def g24_to_rgb(path):
    """G24 → RGB PIL Image"""
    from PIL import Image
    data = open(path, 'rb').read()
    x, y, w, h = struct.unpack_from('<hhhh', data, 0)
    stride = (w * 3 + 3) & ~3
    raw = lzss_decompress(data[8:])
    out = bytearray(w * h * 3)
    for row in range(h):
        sr = (h - 1 - row) * stride
        dr = row * w * 3
        for col in range(w):
            out[dr + col*3 + 0] = raw[sr + col*3 + 2]  # R
            out[dr + col*3 + 1] = raw[sr + col*3 + 1]  # G
            out[dr + col*3 + 2] = raw[sr + col*3 + 0]  # B
    return Image.frombytes('RGB', (w, h), bytes(out))

# ── 命令 ──
def cmd_decode(msk_path, ref_path, out_path):
    """MSK → 灰度 PNG (alpha 通道可视化)"""
    from PIL import Image
    
    msk_data = lzss_decompress(open(msk_path, 'rb').read())
    
    # Type A 检测: 有 4B 头, 值域 0x00-0x10
    if len(msk_data) >= 5:
        tw, th = struct.unpack_from('<HH', msk_data, 0)
        body = msk_data[4:]
        if tw > 0 and th > 0 and tw <= 4096 and th <= 4096 and tw * th == len(body) and max(body) <= 0x10:
            # Type A: 值 ×16 扩展到 0-255
            expanded = bytes([min(255, b * 16) for b in body])
            img = Image.frombytes('L', (tw, th), expanded)
            img.save(out_path)
            print(f"  {os.path.basename(msk_path)} → {os.path.basename(out_path)} ({tw}×{th}) [Type A, ×16]")
            return
    
    # Type B: 从参考文件获取尺寸
    w, h = 0, 0
    if ref_path and os.path.exists(ref_path):
        if ref_path.upper().endswith('.G24'):
            w, h = g24_get_size(ref_path)
        else:
            img = Image.open(ref_path)
            w, h = img.size
    
    # 验证尺寸匹配
    if w > 0 and h > 0 and w * h == len(msk_data):
        img = Image.frombytes('L', (w, h), msk_data)
        img.save(out_path)
        print(f"  {os.path.basename(msk_path)} → {os.path.basename(out_path)} ({w}×{h}) [Type B]")
        return
    
    # 尺寸不匹配: 猜测合理尺寸
    n = len(msk_data)
    best_w, best_h = 0, 0
    for cw in [640, 480, 392, 328, 320, 256, 200, 160]:
        if n % cw == 0:
            ch = n // cw
            if 10 < ch < 4096:
                best_w, best_h = cw, ch
                break
    
    if best_w > 0:
        img = Image.frombytes('L', (best_w, best_h), msk_data[:best_w * best_h])
        img.save(out_path)
        ref_info = f" (G24={w}×{h} 不匹配!)" if w > 0 else ""
        print(f"  {os.path.basename(msk_path)} → {os.path.basename(out_path)} ({best_w}×{best_h}) [猜测]{ref_info}")
    else:
        print(f"  跳过 {os.path.basename(msk_path)}: 无法确定尺寸 ({n}B)")

def cmd_merge(g24_path, msk_path, out_path):
    """G24 + MSK → RGBA PNG"""
    from PIL import Image
    rgb = g24_to_rgb(g24_path)
    w, h = rgb.size
    msk_data = lzss_decompress(open(msk_path, 'rb').read())
    alpha = Image.frombytes('L', (w, h), msk_data[:w * h])
    rgba = rgb.convert('RGBA')
    rgba.putalpha(alpha)
    rgba.save(out_path)
    print(f"  {os.path.basename(g24_path)} + {os.path.basename(msk_path)} → {os.path.basename(out_path)}")

def cmd_encode(png_path, out_path):
    """灰度 PNG → LZSS 压缩 MSK"""
    from PIL import Image
    img = Image.open(png_path).convert('L')
    raw = img.tobytes()
    comp = compress(raw)
    open(out_path, 'wb').write(comp)
    ratio = len(comp) * 100 // len(raw) if raw else 0
    print(f"  {os.path.basename(png_path)} → {os.path.basename(out_path)} ({len(raw)}→{len(comp)}, {ratio}%)")

def cmd_extract_alpha(png_path, out_path):
    """RGBA PNG 的 alpha 通道 → LZSS 压缩 MSK"""
    from PIL import Image
    img = Image.open(png_path)
    if img.mode != 'RGBA':
        print(f"  警告: {png_path} 不是 RGBA, 生成全不透明 MSK")
        w, h = img.size
        raw = b'\xFF' * (w * h)
    else:
        raw = img.getchannel('A').tobytes()
    comp = compress(raw)
    open(out_path, 'wb').write(comp)
    print(f"  {os.path.basename(png_path)} alpha → {os.path.basename(out_path)} ({len(raw)}→{len(comp)})")

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'decode':
        src = sys.argv[2]
        ref = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith('-') else None
        if os.path.isdir(src):
            out_dir = sys.argv[4] if len(sys.argv) > 4 else (sys.argv[3] if len(sys.argv) > 3 and sys.argv[3].startswith('-') else src + '_png')
            # 重新判断参数
            if ref and os.path.isdir(ref):
                out_dir = sys.argv[4] if len(sys.argv) > 4 else src + '_png'
            elif ref and not os.path.isdir(ref):
                out_dir = ref
                ref = None
            os.makedirs(out_dir, exist_ok=True)
            for fn in sorted(os.listdir(src)):
                if not fn.upper().endswith('.MSK'): continue
                base = fn.rsplit('_', 1)[0] if '_M.' in fn.upper() or '_m.' in fn else fn.rsplit('.', 1)[0]
                rp = None
                if ref:
                    for ext in ['.G24', '.g24', '.png', '.PNG']:
                        cand = os.path.join(ref, base + ext)
                        if os.path.exists(cand):
                            rp = cand; break
                op = os.path.join(out_dir, fn.rsplit('.', 1)[0] + '.png')
                cmd_decode(os.path.join(src, fn), rp, op)
        else:
            out = sys.argv[4] if len(sys.argv) > 4 else os.path.splitext(src)[0] + '.png'
            cmd_decode(src, ref, out)

    elif cmd == 'merge':
        g24, msk = sys.argv[2], sys.argv[3]
        if os.path.isdir(g24) and os.path.isdir(msk):
            out_dir = sys.argv[4] if len(sys.argv) > 4 else g24 + '_rgba'
            os.makedirs(out_dir, exist_ok=True)
            for fn in sorted(os.listdir(msk)):
                if not fn.upper().endswith('.MSK'): continue
                base = fn.rsplit('_', 1)[0] if '_M.' in fn.upper() or '_m.' in fn else fn.rsplit('.', 1)[0]
                g24_file = os.path.join(g24, base + '.G24')
                if not os.path.exists(g24_file):
                    print(f"  跳过 {fn}: 找不到 {base}.G24")
                    continue
                op = os.path.join(out_dir, base + '_rgba.png')
                cmd_merge(g24_file, os.path.join(msk, fn), op)
        else:
            out = sys.argv[4] if len(sys.argv) > 4 else os.path.splitext(g24)[0] + '_rgba.png'
            cmd_merge(g24, msk, out)

    elif cmd == 'encode':
        src = sys.argv[2]
        if os.path.isdir(src):
            out_dir = sys.argv[3] if len(sys.argv) > 3 else src + '_msk'
            os.makedirs(out_dir, exist_ok=True)
            for fn in sorted(os.listdir(src)):
                if not fn.lower().endswith('.png'): continue
                op = os.path.join(out_dir, fn.rsplit('.', 1)[0] + '.MSK')
                cmd_encode(os.path.join(src, fn), op)
        else:
            out = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(src)[0] + '.MSK'
            cmd_encode(src, out)

    elif cmd == 'extract_alpha':
        src = sys.argv[2]
        if os.path.isdir(src):
            out_dir = sys.argv[3] if len(sys.argv) > 3 else src + '_msk'
            os.makedirs(out_dir, exist_ok=True)
            for fn in sorted(os.listdir(src)):
                if not fn.lower().endswith('.png'): continue
                base = fn.rsplit('.', 1)[0]
                op = os.path.join(out_dir, base + '_M.MSK')
                cmd_extract_alpha(os.path.join(src, fn), op)
        else:
            out = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(src)[0] + '_M.MSK'
            cmd_extract_alpha(src, out)

    else:
        print(f"未知命令: {cmd}"); print(__doc__); sys.exit(1)

if __name__ == '__main__':
    main()
