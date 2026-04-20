"""
FFA 引擎 LZSS 压缩/解压工具 (纯 Python 实现)
  v1.0, developed by natsuko

  替代 amanomiko_lzss.py (后者需要 liblzss20_64.dll)

用法:
  解压单文件:  python so4_lzss.py d A0_000.SO4
  解压单文件:  python so4_lzss.py d A0_000.SO4 -o A0_000.SO4.dec
  压缩单文件:  python so4_lzss.py e A0_000.SO4.dec -o A0_000.SO4
  批量解压:    python so4_lzss.py d ./so4_raw/ -o ./so4_dec/
  批量压缩:    python so4_lzss.py e ./so4_dec/ -o ./so4_raw/

LZSS 格式:
  Header: uint32_le compressed_size + uint32_le decompressed_size
  Data:   标准 LZSS (4KB 窗口, 初始填充 0x00, 写入起始 0xFEE)
          flag byte LSB-first: 1=literal, 0=match(12bit offset + 4bit length, min=3)
"""

import os
import sys
import struct
import argparse
from pathlib import Path

# ============================================================
# LZSS parameters (FFA engine standard)
# ============================================================

WINDOW_SIZE = 4096       # 0x1000
WINDOW_INIT = 0x00       # 窗口初始填充值
WRITE_POS_INIT = 0xFEE   # 写入起始位置
MIN_MATCH = 3
MAX_MATCH = 18           # 4 bits (0-15) + 3

# ============================================================
# Decompress
# ============================================================

def lzss_decompress(compressed: bytes, raw_size: int) -> bytes:
    """
    LZSS 解压。
    compressed: 不含 8 字节头的纯压缩数据。
    raw_size:   预期解压后大小。
    """
    window = bytearray([WINDOW_INIT] * WINDOW_SIZE)
    wp = WRITE_POS_INIT
    output = bytearray()
    pos = 0

    while len(output) < raw_size and pos < len(compressed):
        flags = compressed[pos]
        pos += 1
        for bit in range(8):
            if len(output) >= raw_size:
                break
            if flags & (1 << bit):
                # literal byte
                if pos >= len(compressed):
                    break
                b = compressed[pos]
                pos += 1
                output.append(b)
                window[wp] = b
                wp = (wp + 1) & 0xFFF
            else:
                # match reference
                if pos + 1 >= len(compressed):
                    break
                lo = compressed[pos]
                hi = compressed[pos + 1]
                pos += 2
                offset = lo | ((hi & 0xF0) << 4)
                length = (hi & 0x0F) + MIN_MATCH
                for k in range(length):
                    if len(output) >= raw_size:
                        break
                    b = window[(offset + k) & 0xFFF]
                    output.append(b)
                    window[wp] = b
                    wp = (wp + 1) & 0xFFF

    return bytes(output)

# ============================================================
# Compress
# ============================================================

def lzss_compress(raw: bytes) -> bytes:
    """
    LZSS 压缩。返回不含 8 字节头的纯压缩数据。
    使用 hash chain 加速匹配查找，比暴力搜索快 30-50 倍。
    """
    window = bytearray([WINDOW_INIT] * WINDOW_SIZE)
    wp = WRITE_POS_INIT
    output = bytearray()
    pos = 0
    n = len(raw)

    # --- hash chain 索引 ---
    HASH_BITS = 12
    HASH_SIZE = 1 << HASH_BITS
    HASH_MASK = HASH_SIZE - 1
    head = [0xFFFF] * HASH_SIZE       # head[hash] → 窗口位置
    chain = [0xFFFF] * WINDOW_SIZE     # chain[pos] → 同 hash 上一个位置
    NIL = 0xFFFF
    MAX_CHAIN = 128                    # 链长上限，防止退化

    def _h(a, b):
        return ((a << 5) ^ b) & HASH_MASK

    # 预填充初始窗口(全0)的 hash chain — 但全0的chain太长没意义，跳过
    # 直接开始压缩，初始窗口的0会自然被匹配到

    while pos < n:
        flag_byte = 0
        flag_pos = len(output)
        output.append(0)
        buf = bytearray()

        for bit in range(8):
            if pos >= n:
                break

            max_search = min(n - pos, MAX_MATCH)
            best_len = 0
            best_off = 0

            # 构建当前字节对的 hash
            b0 = raw[pos]
            b1 = raw[pos + 1] if pos + 1 < n else 0
            h = _h(b0, b1)

            # 遍历 hash chain
            idx = head[h]
            steps = 0
            while idx != NIL and steps < MAX_CHAIN:
                steps += 1
                # 跳过与 wp 重叠的候选（极罕见，安全跳过，仅损失微量压缩率）
                dist = (wp - idx) & 0xFFF
                if dist == 0 or dist > WINDOW_SIZE - MAX_MATCH:
                    idx = chain[idx]
                    continue

                if window[idx] != b0:
                    idx = chain[idx]
                    continue

                # 计算匹配长度（限制在不跨越 wp 的安全范围内）
                ml = 0
                safe_max = min(max_search, dist)
                while (ml < safe_max and
                       window[(idx + ml) & 0xFFF] == raw[pos + ml]):
                    ml += 1

                if ml > best_len:
                    best_len = ml
                    best_off = idx
                    if best_len >= MAX_MATCH:
                        break

                idx = chain[idx]

            # 如果 hash chain 没找到好匹配，对全 0 区域做快速检查
            if best_len < MIN_MATCH and b0 == 0:
                # 窗口中 0xFEE 之前全是 0，检查能匹配多少个 0
                ml = 0
                while ml < max_search and raw[pos + ml] == 0:
                    ml += 1
                if ml >= MIN_MATCH:
                    # 找一个全0的窗口位置（避开 wp）
                    zero_off = 0 if wp != 0 else 1
                    best_len = min(ml, MAX_MATCH)
                    best_off = zero_off

            if best_len >= MIN_MATCH:
                lo = best_off & 0xFF
                hi = ((best_off >> 4) & 0xF0) | ((best_len - MIN_MATCH) & 0x0F)
                buf.append(lo)
                buf.append(hi)
                for k in range(best_len):
                    # 更新 hash chain
                    if pos + 1 < n:
                        h2 = _h(raw[pos], raw[pos + 1])
                    else:
                        h2 = _h(raw[pos], 0)
                    chain[wp] = head[h2]
                    head[h2] = wp
                    window[wp] = raw[pos]
                    wp = (wp + 1) & 0xFFF
                    pos += 1
            else:
                flag_byte |= (1 << bit)
                buf.append(raw[pos])
                if pos + 1 < n:
                    h2 = _h(raw[pos], raw[pos + 1])
                else:
                    h2 = _h(raw[pos], 0)
                chain[wp] = head[h2]
                head[h2] = wp
                window[wp] = raw[pos]
                wp = (wp + 1) & 0xFFF
                pos += 1

        output[flag_pos] = flag_byte
        output.extend(buf)

    return bytes(output)

# ============================================================
# File-level decode/encode (with 8-byte header)
# ============================================================

def decode_file(inpath: str, outpath: str) -> bytes:
    """解压一个带 8 字节头的 LZSS 文件"""
    with open(inpath, 'rb') as fp:
        data = fp.read()

    if len(data) < 8:
        raise ValueError(f"文件太小，不是 LZSS 格式: {inpath}")

    zsize, rawsize = struct.unpack_from('<II', data, 0)
    compressed = data[8:]

    # 验证 zsize
    if zsize > len(compressed):
        # 可能不是 LZSS 压缩文件，直接复制
        print(f"  警告: {Path(inpath).name} 不像 LZSS 格式 "
              f"(zsize=0x{zsize:X} > data={len(compressed)}), 直接复制")
        raw = data
    else:
        raw = lzss_decompress(compressed[:zsize], rawsize)
        if len(raw) != rawsize:
            print(f"  警告: 解压大小不匹配 ({len(raw)} != {rawsize})")

    if outpath:
        with open(outpath, 'wb') as fp:
            fp.write(raw)

    return raw


def encode_file(inpath: str, outpath: str) -> bytes:
    """压缩一个文件，添加 8 字节头"""
    with open(inpath, 'rb') as fp:
        raw = fp.read()

    compressed = lzss_compress(raw)
    header = struct.pack('<II', len(compressed), len(raw))
    result = header + compressed

    if outpath:
        with open(outpath, 'wb') as fp:
            fp.write(result)

    return result

# ============================================================
# 判断文件是否为 LZSS 压缩格式
# ============================================================

def is_lzss_file(filepath: str) -> bool:
    """启发式判断文件是否为 FFA LZSS 格式"""
    try:
        with open(filepath, 'rb') as fp:
            header = fp.read(8)
        if len(header) < 8:
            return False
        zsize, rawsize = struct.unpack_from('<II', header, 0)
        filesize = os.path.getsize(filepath)
        # zsize 应该接近 filesize-8, rawsize 应该 > zsize
        return (zsize > 0 and rawsize > 0
                and zsize <= filesize - 8 + 16  # 允许少量偏差
                and rawsize >= zsize
                and rawsize < 100 * 1024 * 1024)  # < 100MB 合理范围
    except:
        return False

# ============================================================
# Batch
# ============================================================

def batch_decode(input_dir: str, output_dir: str):
    """批量解压文件夹中的 SO4 文件"""
    os.makedirs(output_dir, exist_ok=True)
    inpath = Path(input_dir)

    files = sorted(f for f in inpath.iterdir()
                   if f.is_file() and f.suffix.upper() in ('.SO4', '.DAT', '.BIN', ''))

    if not files:
        # 尝试所有文件
        files = sorted(f for f in inpath.iterdir() if f.is_file())

    if not files:
        print(f"未找到文件: {input_dir}")
        return

    print(f"扫描 {len(files)} 个文件")
    print("-" * 50)

    ok = skip = fail = 0
    for fp in files:
        outfile = os.path.join(output_dir, fp.name + '.dec')
        if not is_lzss_file(str(fp)):
            # 不是 LZSS，直接复制
            print(f"  {fp.name}: 非 LZSS，直接复制")
            with open(str(fp), 'rb') as f_in:
                raw = f_in.read()
            with open(outfile, 'wb') as f_out:
                f_out.write(raw)
            skip += 1
            continue
        try:
            raw = decode_file(str(fp), outfile)
            print(f"  {fp.name} → {fp.name}.dec ({os.path.getsize(str(fp))} → {len(raw)} bytes)")
            ok += 1
        except Exception as e:
            fail += 1
            print(f"  {fp.name}: 失败 - {e}")

    print("-" * 50)
    print(f"完成: {ok} 解压 / {skip} 复制 / {fail} 失败")


def batch_encode(input_dir: str, output_dir: str):
    """批量压缩文件夹中的 .dec 文件"""
    os.makedirs(output_dir, exist_ok=True)
    inpath = Path(input_dir)

    files = sorted(f for f in inpath.iterdir() if f.is_file())
    if not files:
        print(f"未找到文件: {input_dir}")
        return

    print(f"找到 {len(files)} 个文件")
    print("-" * 50)

    ok = fail = 0
    for fp in files:
        # 去掉 .dec 后缀
        if fp.name.endswith('.dec'):
            outname = fp.name[:-4]
        else:
            outname = fp.name
        outfile = os.path.join(output_dir, outname)

        try:
            result = encode_file(str(fp), outfile)
            raw_size = os.path.getsize(str(fp))
            print(f"  {fp.name} → {outname} ({raw_size} → {len(result)} bytes)")
            ok += 1
        except Exception as e:
            fail += 1
            print(f"  {fp.name}: 失败 - {e}")

    print("-" * 50)
    print(f"完成: {ok} 压缩 / {fail} 失败")

# ============================================================
# Main
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description='FFA 引擎 LZSS 压缩/解压工具 (纯 Python)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python so4_lzss.py d A0_000.SO4                   # 解压 → A0_000.SO4.dec
  python so4_lzss.py d A0_000.SO4 -o decoded.bin     # 指定输出
  python so4_lzss.py e A0_000.SO4.dec                # 压缩 → A0_000.SO4
  python so4_lzss.py d ./so4_raw/ -o ./so4_dec/      # 批量解压
  python so4_lzss.py e ./so4_dec/ -o ./so4_raw/      # 批量压缩""")

    ap.add_argument('mode', choices=['d', 'e'],
                    help='d=解压(decode), e=压缩(encode)')
    ap.add_argument('input', help='输入文件或文件夹')
    ap.add_argument('-o', '--output', default=None,
                    help='输出文件或文件夹')
    args = ap.parse_args()

    inp = Path(args.input)

    if args.mode == 'd':
        if inp.is_dir():
            outdir = args.output or str(inp) + '_dec'
            batch_decode(str(inp), outdir)
        elif inp.is_file():
            outpath = args.output or (str(inp) + '.dec')
            raw = decode_file(str(inp), outpath)
            print(f"解压完成: {len(raw)} bytes → {outpath}")
        else:
            print(f"路径不存在: {args.input}")
            sys.exit(1)

    elif args.mode == 'e':
        if inp.is_dir():
            outdir = args.output or str(inp) + '_enc'
            batch_encode(str(inp), outdir)
        elif inp.is_file():
            if args.output:
                outpath = args.output
            elif inp.name.endswith('.dec'):
                outpath = str(inp)[:-4]
            else:
                outpath = str(inp) + '.lzss'
            result = encode_file(str(inp), outpath)
            print(f"压缩完成: {len(result)} bytes → {outpath}")
        else:
            print(f"路径不存在: {args.input}")
            sys.exit(1)


if __name__ == '__main__':
    main()
