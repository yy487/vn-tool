#!/usr/bin/env python3
"""
Interlude Engine VTV → PNG 批量转换工具
用法: python vtv_batch.py
"""

import struct
import os
import sys
import zlib
import io

# ========== 配置 ==========
INPUT_DIR  = r"E:\GAL\ads\cg"
OUTPUT_DIR = r"E:\GAL\ads\VTV"
# ==========================


def decompress_lzss(compressed_data: bytes, output_size: int, param_4: int) -> bytearray:
    bVar1 = param_4 & 0xF
    uVar7 = (1 << bVar1) - 1
    signed_p4 = param_4 if param_4 < 128 else param_4 - 256
    _param_4 = 0xFFFFFFFF if (-1 < signed_p4) else uVar7

    literal_offset = struct.unpack_from('<I', compressed_data, 0)[0]
    bitstream_pos = 4
    literal_pos = literal_offset

    output = bytearray(output_size + 1024)
    out_pos = 0
    ctrl_word = 0xFFFF
    remaining = output_size

    while remaining > 0:
        if ctrl_word == 0xFFFF:
            raw = struct.unpack_from('<H', compressed_data, bitstream_pos)[0]
            signed_val = raw if raw < 0x8000 else raw - 0x10000
            ctrl_word = signed_val | 0xFFFF0000
            ctrl_word &= 0xFFFFFFFF
            bitstream_pos += 2

        if (ctrl_word & 1) == 0:
            ref_word = struct.unpack_from('<H', compressed_data, bitstream_pos)[0]
            match_len_code = ref_word & uVar7
            back_offset = ref_word >> bVar1
            bitstream_pos += 2

            if back_offset == 0:
                back_offset = struct.unpack_from('<H', compressed_data, bitstream_pos)[0]
                bitstream_pos += 2

            src_pos = out_pos - back_offset

            if match_len_code == _param_4:
                match_len_code = compressed_data[literal_pos] + _param_4
                literal_pos += 1

            total_copy = match_len_code + 3
            remaining -= total_copy

            for _ in range(total_copy):
                if 0 <= src_pos < len(output):
                    output[out_pos] = output[src_pos]
                else:
                    output[out_pos] = 0
                out_pos += 1
                src_pos += 1
        else:
            output[out_pos] = compressed_data[literal_pos]
            out_pos += 1
            literal_pos += 1
            remaining -= 1

        ctrl_word = (ctrl_word >> 1) & 0xFFFFFFFF

    return output[:output_size]


def bgra_to_png(pixel_data: bytearray, width: int, height: int) -> bytes:
    """BGRA像素 → PNG字节"""
    row_size = width * 4
    png_rows = bytearray()
    for y in range(height):
        png_rows.append(0)  # filter: None
        row_start = y * row_size
        for x in range(width):
            off = row_start + x * 4
            if off + 3 < len(pixel_data):
                b, g, r, a = pixel_data[off], pixel_data[off+1], pixel_data[off+2], pixel_data[off+3]
                png_rows.extend([r, g, b, 255])
            else:
                png_rows.extend([0, 0, 0, 255])

    def make_chunk(ctype, cdata):
        chunk = ctype + cdata
        crc = zlib.crc32(chunk) & 0xFFFFFFFF
        return struct.pack('>I', len(cdata)) + chunk + struct.pack('>I', crc)

    buf = io.BytesIO()
    buf.write(b'\x89PNG\r\n\x1a\n')
    buf.write(make_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)))
    buf.write(make_chunk(b'IDAT', zlib.compress(bytes(png_rows), 6)))
    buf.write(make_chunk(b'IEND', b''))
    return buf.getvalue()


def rgb565_to_png(pixel_data: bytearray, width: int, height: int) -> bytes:
    """16位RGB565 → PNG字节"""
    png_rows = bytearray()
    for y in range(height):
        png_rows.append(0)
        for x in range(width):
            off = (y * width + x) * 2
            if off + 1 < len(pixel_data):
                px = struct.unpack_from('<H', pixel_data, off)[0]
                r = ((px >> 11) & 0x1F) * 255 // 31
                g = ((px >> 5) & 0x3F) * 255 // 63
                b = (px & 0x1F) * 255 // 31
                png_rows.extend([r, g, b, 255])
            else:
                png_rows.extend([0, 0, 0, 255])

    def make_chunk(ctype, cdata):
        chunk = ctype + cdata
        crc = zlib.crc32(chunk) & 0xFFFFFFFF
        return struct.pack('>I', len(cdata)) + chunk + struct.pack('>I', crc)

    buf = io.BytesIO()
    buf.write(b'\x89PNG\r\n\x1a\n')
    buf.write(make_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)))
    buf.write(make_chunk(b'IDAT', zlib.compress(bytes(png_rows), 6)))
    buf.write(make_chunk(b'IEND', b''))
    return buf.getvalue()


def decode_vtv_to_png(vtv_path: str, png_path: str) -> bool:
    with open(vtv_path, 'rb') as f:
        data = bytearray(f.read())

    # 判断头部
    has_ucat = (
        (data[1] - data[0]) & 0xFF == 0x18 and
        data[2] == data[1] and
        (data[3] - data[0]) & 0xFF == 0x04
    )

    img_offset = 0xA8 if has_ucat else 0x10

    if has_ucat:
        xor_key = [0x55, 0x43, 0x41, 0x54]
        for i in range(4):
            data[img_offset + i] ^= xor_key[i]

    width  = struct.unpack_from('<H', data, img_offset)[0]
    height = struct.unpack_from('<H', data, img_offset + 2)[0]
    fmt    = struct.unpack_from('<H', data, img_offset + 4)[0]

    if width == 0 or height == 0 or width > 4096 or height > 4096:
        return False

    is_16bit = (fmt & 0xFF00) == 0x300
    output_size = width * height * (2 if is_16bit else 4)

    compressed = bytes(data[img_offset + 8:])
    pixels = decompress_lzss(compressed, output_size, fmt & 0xFF)

    if is_16bit:
        png_data = rgb565_to_png(pixels, width, height)
    else:
        png_data = bgra_to_png(pixels, width, height)

    with open(png_path, 'wb') as f:
        f.write(png_data)
    return True


def main():
    input_dir  = INPUT_DIR
    output_dir = OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    files = [f for f in os.listdir(input_dir) if f.lower().endswith('.vtv')]
    files.sort()
    total = len(files)
    print(f"共 {total} 个VTV文件")
    print(f"输入: {input_dir}")
    print(f"输出: {output_dir}\n")

    ok = 0
    fail = 0
    for i, fname in enumerate(files, 1):
        src = os.path.join(input_dir, fname)
        dst = os.path.join(output_dir, os.path.splitext(fname)[0] + '.png')
        try:
            if decode_vtv_to_png(src, dst):
                ok += 1
                print(f"[{i}/{total}] OK  {fname}")
            else:
                fail += 1
                print(f"[{i}/{total}] SKIP {fname} (异常尺寸)")
        except Exception as e:
            fail += 1
            print(f"[{i}/{total}] FAIL {fname}: {e}")

    print(f"\n完成: 成功={ok} 失败={fail} 总计={total}")


if __name__ == '__main__':
    main()
