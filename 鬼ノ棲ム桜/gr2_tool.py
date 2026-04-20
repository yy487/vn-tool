#!/usr/bin/env python3
"""
gr2_tool.py - 鬼ノ棲ム桜 (ONI engine) GR2 图像格式转换工具

GR2 格式结构:
  [0x00-0x27]  BITMAPINFOHEADER (40 bytes) - 标准 Windows BMP 信息头
  [0x28-0x4B]  Extra header (36 bytes):
               +0x00 (8B)  游戏标题 (SJIS, null-padded)
               +0x08 (12B) 保留 (全零)
               +0x14 (4B)  版本/标志 (uint32, 通常=1)
               +0x18 (4B)  未知参数 (uint32, 通常=0x1f)
               +0x1c (4B)  宽度 (uint32, 与 BITMAPINFOHEADER 一致)
               +0x20 (4B)  高度 (uint32, 与 BITMAPINFOHEADER 一致)
  [0x4C-EOF]   LZSS 压缩数据 (标准 4KB 窗口, 初始写入位置 0xFEE)

像素数据: BGR bottom-up (与 BMP 一致), 24bpp
压缩: 标准 LZSS - 12位偏移 + 4位长度, 最小匹配长度3

使用方法:
  python gr2_tool.py decode <input.gr2> [output.png]
  python gr2_tool.py encode <input.png> [output.gr2]
  python gr2_tool.py batch_decode <input_dir> [output_dir]
  python gr2_tool.py batch_encode <input_dir> [output_dir]
  python gr2_tool.py info <input.gr2>
"""

import struct
import sys
import os
from pathlib import Path


# ============================================================
# LZSS 压缩/解压
# ============================================================

WINDOW_SIZE = 4096       # 4KB 滑动窗口
WINDOW_MASK = 0xFFF
WINDOW_INIT = 0xFEE      # 初始写入位置
MAX_MATCH_LEN = 18       # 最大匹配长度 (4位 + 3 = 15 + 3)
MIN_MATCH_LEN = 3        # 最小匹配长度
THRESHOLD = MIN_MATCH_LEN


def lzss_decompress(compressed: bytes) -> bytes:
    """标准 LZSS 解压 (4KB 窗口, 12位偏移 + 4位长度)"""
    window = bytearray(WINDOW_SIZE)
    win_pos = WINDOW_INIT
    output = bytearray()

    src = 0
    src_len = len(compressed)
    flags = 0

    while src < src_len:
        flags >>= 1
        if (flags & 0x100) == 0:
            if src >= src_len:
                break
            flags = 0xFF00 | compressed[src]
            src += 1

        if flags & 1:
            # bit=1: literal byte
            if src >= src_len:
                break
            b = compressed[src]
            src += 1
            output.append(b)
            window[win_pos] = b
            win_pos = (win_pos + 1) & WINDOW_MASK
        else:
            # bit=0: match reference
            if src + 1 >= src_len:
                break
            b1 = compressed[src]
            b2 = compressed[src + 1]
            src += 2

            offset = b1 | ((b2 & 0xF0) << 4)
            length = (b2 & 0x0F) + THRESHOLD

            for j in range(length):
                b = window[(offset + j) & WINDOW_MASK]
                output.append(b)
                window[win_pos] = b
                win_pos = (win_pos + 1) & WINDOW_MASK

    return bytes(output)


def lzss_compress(data: bytes) -> bytes:
    """标准 LZSS 压缩 (4KB 窗口, 12位偏移 + 4位长度)"""
    window = bytearray(WINDOW_SIZE)
    win_pos = WINDOW_INIT
    output = bytearray()

    src = 0
    src_len = len(data)

    # 临时缓冲: 每组最多8个编码单元 (1 flag byte + 最多 8*(2 bytes))
    while src < src_len:
        flag_byte = 0
        group_buf = bytearray()

        for bit in range(8):
            if src >= src_len:
                break

            # 在窗口中搜索最长匹配
            best_offset = 0
            best_length = 0

            # 搜索范围: 窗口中所有有效位置
            max_search = min(src, WINDOW_SIZE)
            for search_len_candidate in range(MIN_MATCH_LEN, MAX_MATCH_LEN + 1):
                if src + search_len_candidate > src_len:
                    break
                # 只有当更长时才更新
                found = False
                for back in range(1, WINDOW_SIZE):
                    match = True
                    for k in range(search_len_candidate):
                        if window[(win_pos - back + k) & WINDOW_MASK] != data[src + k]:
                            match = False
                            break
                    if match:
                        best_offset = (win_pos - back) & WINDOW_MASK
                        best_length = search_len_candidate
                        found = True
                        break
                if not found:
                    break

            if best_length >= MIN_MATCH_LEN:
                # 输出匹配引用
                len_code = best_length - THRESHOLD
                b1 = best_offset & 0xFF
                b2 = ((best_offset >> 4) & 0xF0) | (len_code & 0x0F)
                group_buf.append(b1)
                group_buf.append(b2)
                # 推进窗口
                for k in range(best_length):
                    window[win_pos] = data[src + k]
                    win_pos = (win_pos + 1) & WINDOW_MASK
                src += best_length
            else:
                # 输出字面量
                flag_byte |= (1 << bit)
                group_buf.append(data[src])
                window[win_pos] = data[src]
                win_pos = (win_pos + 1) & WINDOW_MASK
                src += 1

        output.append(flag_byte)
        output.extend(group_buf)

    return bytes(output)


def lzss_compress_fast(data: bytes) -> bytes:
    """
    快速 LZSS 压缩 (使用哈希链加速匹配查找)
    比朴素版快 100x+, 压缩率略低但完全兼容
    """
    src_len = len(data)
    window = bytearray(WINDOW_SIZE)
    win_pos = WINDOW_INIT
    
    # 哈希链: 基于3字节前缀的快速查找
    HASH_SIZE = 4096
    hash_head = [-1] * HASH_SIZE  # 每个哈希桶的最新位置 (在data中的偏移)
    hash_prev = [-1] * src_len    # 链表: 同哈希桶的前一个位置
    
    def hash3(pos):
        if pos + 2 >= src_len:
            return 0
        return ((data[pos] << 4) ^ (data[pos+1] << 2) ^ data[pos+2]) & (HASH_SIZE - 1)
    
    output = bytearray()
    src = 0
    
    while src < src_len:
        flag_byte = 0
        group_buf = bytearray()
        
        for bit in range(8):
            if src >= src_len:
                break
            
            best_offset = 0
            best_length = 0
            
            if src + MIN_MATCH_LEN <= src_len:
                h = hash3(src)
                candidate = hash_head[h]
                max_chain = 128  # 限制搜索链长度
                
                while candidate >= 0 and max_chain > 0:
                    # candidate 是 data 中的位置
                    dist = src - candidate
                    if dist > WINDOW_SIZE or dist <= 0:
                        break
                    
                    # 检查匹配长度
                    ml = 0
                    max_ml = min(MAX_MATCH_LEN, src_len - src)
                    while ml < max_ml and data[candidate + ml] == data[src + ml]:
                        ml += 1
                    
                    if ml >= MIN_MATCH_LEN and ml > best_length:
                        best_length = ml
                        # 计算窗口中的偏移
                        best_offset = (win_pos - dist) & WINDOW_MASK
                        if best_length == MAX_MATCH_LEN:
                            break
                    
                    candidate = hash_prev[candidate]
                    max_chain -= 1
                
                # 更新哈希链
                h = hash3(src)
                hash_prev[src] = hash_head[h]
                hash_head[h] = src
            
            if best_length >= MIN_MATCH_LEN:
                # 匹配引用
                len_code = best_length - THRESHOLD
                b1 = best_offset & 0xFF
                b2 = ((best_offset >> 4) & 0xF0) | (len_code & 0x0F)
                group_buf.append(b1)
                group_buf.append(b2)
                
                # 更新窗口和哈希链 (跳过的字节也要加入哈希)
                for k in range(best_length):
                    window[win_pos] = data[src + k]
                    win_pos = (win_pos + 1) & WINDOW_MASK
                    if k > 0 and src + k + MIN_MATCH_LEN <= src_len:
                        h2 = hash3(src + k)
                        hash_prev[src + k] = hash_head[h2]
                        hash_head[h2] = src + k
                src += best_length
            else:
                # 字面量
                flag_byte |= (1 << bit)
                group_buf.append(data[src])
                window[win_pos] = data[src]
                win_pos = (win_pos + 1) & WINDOW_MASK
                src += 1
        
        output.append(flag_byte)
        output.extend(group_buf)
    
    return bytes(output)


# ============================================================
# GR2 格式读写
# ============================================================

GR2_BMP_HEADER_SIZE = 0x28   # BITMAPINFOHEADER
GR2_EXTRA_HEADER_SIZE = 0x24  # Extra header
GR2_TOTAL_HEADER_SIZE = GR2_BMP_HEADER_SIZE + GR2_EXTRA_HEADER_SIZE  # 0x4C

# 默认游戏标题 (SJIS 编码的 "鬼棲桜")
DEFAULT_GAME_TITLE = b'\x8b\x53\x90\xb1\x8d\xf7'


def read_gr2(filepath: str) -> dict:
    """
    读取 GR2 文件，返回解析结果字典
    
    Returns:
        {
            'width': int, 'height': int, 'bpp': int,
            'title': bytes, 'version': int, 'param': int,
            'pixels': bytes  (BGR, bottom-up)
        }
    """
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if len(data) < GR2_TOTAL_HEADER_SIZE:
        raise ValueError(f"文件太小: {len(data)} bytes, 最少需要 {GR2_TOTAL_HEADER_SIZE}")
    
    # 解析 BITMAPINFOHEADER
    bi_size = struct.unpack_from('<I', data, 0)[0]
    if bi_size != 0x28:
        raise ValueError(f"无效的 BITMAPINFOHEADER 大小: 0x{bi_size:x} (期望 0x28)")
    
    width = struct.unpack_from('<i', data, 4)[0]
    height = struct.unpack_from('<i', data, 8)[0]
    planes = struct.unpack_from('<H', data, 12)[0]
    bpp = struct.unpack_from('<H', data, 14)[0]
    
    if bpp not in (16, 24):
        raise ValueError(f"不支持的色深: {bpp}bpp (仅支持 16/24)")
    
    # 解析 Extra header
    title = data[0x28:0x34]  # 12 bytes (game title + padding)
    version = struct.unpack_from('<I', data, 0x3C)[0]
    param = struct.unpack_from('<I', data, 0x40)[0]
    ext_width = struct.unpack_from('<I', data, 0x44)[0]
    ext_height = struct.unpack_from('<I', data, 0x48)[0]
    
    # LZSS 解压
    compressed = data[GR2_TOTAL_HEADER_SIZE:]
    pixels = lzss_decompress(compressed)
    
    # 验证解压后大小
    if bpp == 24:
        expected = width * height * 3
    else:
        expected = width * height * 2
    
    # 允许±1字节的误差 (LZSS流末尾可能多出1字节)
    if abs(len(pixels) - expected) > 1:
        print(f"[警告] 解压大小不匹配: {len(pixels)} vs 期望 {expected}", file=sys.stderr)
    
    pixels = pixels[:expected]  # 截断到精确大小
    
    return {
        'width': width,
        'height': height,
        'bpp': bpp,
        'title': title,
        'version': version,
        'param': param,
        'pixels': pixels,
    }


def write_gr2(filepath: str, width: int, height: int, pixels_bgr: bytes,
              bpp: int = 24, title: bytes = None, version: int = 1, param: int = 0x1f):
    """
    将 BGR bottom-up 像素数据压缩写入 GR2 文件
    """
    if title is None:
        title = DEFAULT_GAME_TITLE
    
    # 构建 BITMAPINFOHEADER
    bmp_hdr = bytearray(GR2_BMP_HEADER_SIZE)
    struct.pack_into('<I', bmp_hdr, 0, 0x28)       # biSize
    struct.pack_into('<i', bmp_hdr, 4, width)       # biWidth
    struct.pack_into('<i', bmp_hdr, 8, height)      # biHeight
    struct.pack_into('<H', bmp_hdr, 12, 1)          # biPlanes
    struct.pack_into('<H', bmp_hdr, 14, bpp)        # biBitCount
    struct.pack_into('<I', bmp_hdr, 16, 0)          # biCompression
    struct.pack_into('<I', bmp_hdr, 20, 0)          # biSizeImage
    struct.pack_into('<i', bmp_hdr, 24, 2800)       # biXPelsPerMeter
    struct.pack_into('<i', bmp_hdr, 28, 2800)       # biYPelsPerMeter
    struct.pack_into('<I', bmp_hdr, 32, 0)          # biClrUsed
    struct.pack_into('<I', bmp_hdr, 36, 0)          # biClrImportant
    
    # 构建 Extra header
    ext_hdr = bytearray(GR2_EXTRA_HEADER_SIZE)
    # 写入游戏标题 (前12字节)
    title_bytes = title[:12]
    ext_hdr[:len(title_bytes)] = title_bytes
    struct.pack_into('<I', ext_hdr, 0x14, version)
    struct.pack_into('<I', ext_hdr, 0x18, param)
    struct.pack_into('<I', ext_hdr, 0x1C, width)
    struct.pack_into('<I', ext_hdr, 0x20, height)
    
    # LZSS 压缩
    compressed = lzss_compress_fast(pixels_bgr)
    
    with open(filepath, 'wb') as f:
        f.write(bmp_hdr)
        f.write(ext_hdr)
        f.write(compressed)


# ============================================================
# PNG 转换
# ============================================================

def gr2_to_png(gr2_path: str, png_path: str):
    """GR2 → PNG 转换"""
    info = read_gr2(gr2_path)
    width = info['width']
    height = info['height']
    bpp = info['bpp']
    pixels = info['pixels']
    
    try:
        from PIL import Image
    except ImportError:
        print("错误: 需要 Pillow 库。请运行: pip install Pillow", file=sys.stderr)
        sys.exit(1)
    
    if bpp == 24:
        # BGR bottom-up → RGB
        img = Image.frombytes('RGB', (width, height), pixels, 'raw', 'BGR')
        # BMP 是 bottom-up, 需要翻转
        img = img.transpose(Image.FLIP_TOP_BOTTOM)
    elif bpp == 16:
        # RGB555: 每像素2字节, gggbbbbb 0rrrrrgg
        # 需要展开为 RGB24
        rgb_data = bytearray(width * height * 3)
        for i in range(width * height):
            lo = pixels[i * 2]
            hi = pixels[i * 2 + 1]
            val = lo | (hi << 8)
            r5 = (val >> 10) & 0x1F
            g5 = (val >> 5) & 0x1F
            b5 = val & 0x1F
            rgb_data[i * 3] = round(r5 * 255 / 31)
            rgb_data[i * 3 + 1] = round(g5 * 255 / 31)
            rgb_data[i * 3 + 2] = round(b5 * 255 / 31)
        img = Image.frombytes('RGB', (width, height), bytes(rgb_data))
        img = img.transpose(Image.FLIP_TOP_BOTTOM)
    else:
        raise ValueError(f"不支持的色深: {bpp}bpp")
    
    img.save(png_path)
    return info


def png_to_gr2(png_path: str, gr2_path: str, title: bytes = None,
               ref_gr2: str = None):
    """
    PNG → GR2 转换
    
    Args:
        png_path: 输入 PNG 路径
        gr2_path: 输出 GR2 路径
        title: 游戏标题 (SJIS bytes), 默认 "鬼棲桜"
        ref_gr2: 可选参考 GR2 文件 (复制 title/version/param)
    """
    try:
        from PIL import Image
    except ImportError:
        print("错误: 需要 Pillow 库。请运行: pip install Pillow", file=sys.stderr)
        sys.exit(1)
    
    img = Image.open(png_path).convert('RGB')
    width, height = img.size
    
    # 翻转为 bottom-up
    img = img.transpose(Image.FLIP_TOP_BOTTOM)
    
    # RGB → BGR
    r, g, b = img.split()
    img_bgr = Image.merge('RGB', (b, g, r))
    pixels_bgr = img_bgr.tobytes()
    
    # 从参考文件复制元数据
    version = 1
    param = 0x1f
    if ref_gr2 and os.path.exists(ref_gr2):
        ref_info = read_gr2(ref_gr2)
        title = title or ref_info['title']
        version = ref_info['version']
        param = ref_info['param']
    
    write_gr2(gr2_path, width, height, pixels_bgr, bpp=24,
              title=title, version=version, param=param)


def show_info(gr2_path: str):
    """显示 GR2 文件信息"""
    with open(gr2_path, 'rb') as f:
        data = f.read(GR2_TOTAL_HEADER_SIZE + 16)
    
    if len(data) < GR2_TOTAL_HEADER_SIZE:
        print(f"错误: 文件太小 ({len(data)} bytes)")
        return
    
    bi_size = struct.unpack_from('<I', data, 0)[0]
    width = struct.unpack_from('<i', data, 4)[0]
    height = struct.unpack_from('<i', data, 8)[0]
    bpp = struct.unpack_from('<H', data, 14)[0]
    
    title_raw = data[0x28:0x34]
    try:
        title = title_raw.rstrip(b'\x00').decode('shift_jis')
    except:
        title = repr(title_raw)
    
    version = struct.unpack_from('<I', data, 0x3C)[0]
    param = struct.unpack_from('<I', data, 0x40)[0]
    ext_w = struct.unpack_from('<I', data, 0x44)[0]
    ext_h = struct.unpack_from('<I', data, 0x48)[0]
    
    file_size = os.path.getsize(gr2_path)
    comp_size = file_size - GR2_TOTAL_HEADER_SIZE
    if bpp == 24:
        raw_size = width * height * 3
    else:
        raw_size = width * height * 2
    
    print(f"文件: {gr2_path}")
    print(f"大小: {file_size:,} bytes")
    print(f"─── BITMAPINFOHEADER ───")
    print(f"  尺寸: {width} × {height}")
    print(f"  色深: {bpp}bpp")
    print(f"─── Extra Header ───")
    print(f"  标题: {title}")
    print(f"  版本: {version}")
    print(f"  参数: 0x{param:x}")
    print(f"  尺寸: {ext_w} × {ext_h}")
    print(f"─── 压缩信息 ───")
    print(f"  压缩数据: {comp_size:,} bytes")
    print(f"  原始大小: {raw_size:,} bytes (估算)")
    print(f"  压缩率: {comp_size/raw_size:.1%}" if raw_size > 0 else "")


# ============================================================
# 批量处理
# ============================================================

def batch_decode(input_dir: str, output_dir: str):
    """批量 GR2 → PNG"""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    files = sorted(input_path.glob('*.gr2')) + sorted(input_path.glob('*.GR2'))
    if not files:
        print(f"在 {input_dir} 中未找到 .gr2 文件")
        return
    
    print(f"找到 {len(files)} 个 GR2 文件")
    ok = 0
    fail = 0
    for f in files:
        out = output_path / (f.stem + '.png')
        try:
            gr2_to_png(str(f), str(out))
            ok += 1
            print(f"  ✓ {f.name} → {out.name}")
        except Exception as e:
            fail += 1
            print(f"  ✗ {f.name}: {e}")
    
    print(f"\n完成: {ok} 成功, {fail} 失败")


def batch_encode(input_dir: str, output_dir: str):
    """批量 PNG → GR2"""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    files = sorted(input_path.glob('*.png')) + sorted(input_path.glob('*.PNG'))
    if not files:
        print(f"在 {input_dir} 中未找到 .png 文件")
        return
    
    print(f"找到 {len(files)} 个 PNG 文件")
    ok = 0
    fail = 0
    for f in files:
        out = output_path / (f.stem + '.gr2')
        try:
            png_to_gr2(str(f), str(out))
            ok += 1
            print(f"  ✓ {f.name} → {out.name}")
        except Exception as e:
            fail += 1
            print(f"  ✗ {f.name}: {e}")
    
    print(f"\n完成: {ok} 成功, {fail} 失败")


# ============================================================
# CLI
# ============================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    
    if cmd == 'decode':
        if len(sys.argv) < 3:
            print("用法: gr2_tool.py decode <input.gr2> [output.png]")
            sys.exit(1)
        inp = sys.argv[2]
        out = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(inp)[0] + '.png'
        info = gr2_to_png(inp, out)
        print(f"解码完成: {inp} → {out}")
        print(f"  尺寸: {info['width']}×{info['height']}, {info['bpp']}bpp")
    
    elif cmd == 'encode':
        if len(sys.argv) < 3:
            print("用法: gr2_tool.py encode <input.png> [output.gr2] [--ref original.gr2]")
            sys.exit(1)
        inp = sys.argv[2]
        ref = None
        out = None
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == '--ref' and i + 1 < len(sys.argv):
                ref = sys.argv[i + 1]
                i += 2
            else:
                out = sys.argv[i]
                i += 1
        if out is None:
            out = os.path.splitext(inp)[0] + '.gr2'
        png_to_gr2(inp, out, ref_gr2=ref)
        print(f"编码完成: {inp} → {out}")
        print(f"  文件大小: {os.path.getsize(out):,} bytes")
    
    elif cmd == 'batch_decode':
        if len(sys.argv) < 3:
            print("用法: gr2_tool.py batch_decode <input_dir> [output_dir]")
            sys.exit(1)
        inp_dir = sys.argv[2]
        out_dir = sys.argv[3] if len(sys.argv) > 3 else inp_dir + '_png'
        batch_decode(inp_dir, out_dir)
    
    elif cmd == 'batch_encode':
        if len(sys.argv) < 3:
            print("用法: gr2_tool.py batch_encode <input_dir> [output_dir]")
            sys.exit(1)
        inp_dir = sys.argv[2]
        out_dir = sys.argv[3] if len(sys.argv) > 3 else inp_dir + '_gr2'
        batch_encode(inp_dir, out_dir)
    
    elif cmd == 'info':
        if len(sys.argv) < 3:
            print("用法: gr2_tool.py info <input.gr2>")
            sys.exit(1)
        show_info(sys.argv[2])
    
    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
