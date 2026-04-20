#!/usr/bin/env python3
"""
Interlude Engine VTV 图像解码工具
逆向自 InterludeWin.exe

VTV格式：
- [0x00-0xA7] 168字节外层头部（前4字节XOR后恰好呈现"OggS"假象）
- [0xA8-...]   图片数据（前4字节被 XOR "UCAT" (55 43 41 54) 加密）

图片数据头（解密后）：
- uint16 width
- uint16 height
- uint16 format:
    高字节: 0x03=16位色(RGB565?), 其他=32位色(BGRA)
    低4位: LZSS偏移位宽(bVar1)
    bit7: 长度扩展标志
- uint16 reserved
- 压缩数据（LZSS变种）

LZSS变种压缩：
- 前4字节(int32) = 字面量区偏移（相对于压缩数据起始）
- 偏移+4 = 控制位流区（uint16数组）
- 字面量区 = 未压缩字节

解压流程：
- 控制字（uint16），每bit从低到高处理，用完16bit后读下一个
- bit=1: 从字面量区复制1字节
- bit=0: 从位流区读uint16, 低bVar1位=匹配长度码, 高位>>bVar1=回溯偏移
         如果偏移==0则从下一个uint16读取偏移
         如果长度码==max_len则从字面量区读1字节做扩展
         最终长度 = 长度码 + 3
         从输出的 (当前位置-偏移) 处复制
"""

import struct
import sys
import os
import io


def decompress_lzss(compressed_data: bytes, output_size: int, param_4: int) -> bytearray:
    """
    Interlude LZSS变种解压
    
    Args:
        compressed_data: 压缩数据（从图片头偏移+8开始）
        output_size: 预期输出大小（字节数）
        param_4: format字段低字节
    """
    bVar1 = param_4 & 0xF             # 偏移位宽
    uVar7 = (1 << bVar1) - 1          # 长度掩码 / 最大匹配长度码
    
    # 高bit决定_param_4
    signed_p4 = param_4 if param_4 < 128 else param_4 - 256
    if -1 < signed_p4:  # param_4 < 0x80
        _param_4 = 0xFFFFFFFF  # 禁用长度扩展
    else:
        _param_4 = uVar7
    
    # 解析压缩数据结构
    literal_offset = struct.unpack_from('<I', compressed_data, 0)[0]
    
    # 位流区从偏移4开始（uint16数组）
    bitstream_pos = 4  # 字节偏移，指向位流区
    # 字面量区
    literal_pos = literal_offset  # 字节偏移，指向字面量区
    
    output = bytearray(output_size + 1024)  # 多分配一点防越界
    out_pos = 0
    
    # 控制字
    ctrl_word = 0xFFFF  # 初始值，触发首次读取
    
    remaining = output_size
    
    while remaining > 0:
        # 需要新的控制字？
        if ctrl_word == 0xFFFF:
            raw = struct.unpack_from('<H', compressed_data, bitstream_pos)[0]
            # (int)(short)*puVar5 | 0xffff0000
            signed_val = raw if raw < 0x8000 else raw - 0x10000
            ctrl_word = signed_val | 0xFFFF0000
            ctrl_word &= 0xFFFFFFFF
            bitstream_pos += 2
        
        if (ctrl_word & 1) == 0:
            # 匹配引用
            ref_word = struct.unpack_from('<H', compressed_data, bitstream_pos)[0]
            match_len_code = ref_word & uVar7
            back_offset = ref_word >> bVar1
            bitstream_pos += 2
            
            if back_offset == 0:
                back_offset = struct.unpack_from('<H', compressed_data, bitstream_pos)[0]
                bitstream_pos += 2
            
            # 回溯源位置
            src_pos = out_pos - back_offset
            
            # 长度扩展
            if match_len_code == _param_4:
                match_len_code = compressed_data[literal_pos] + _param_4
                literal_pos += 1
            
            total_copy = match_len_code + 3
            remaining -= total_copy
            
            # 逐字节复制（因为可能有重叠）
            for _ in range(total_copy):
                if src_pos >= 0 and src_pos < len(output):
                    output[out_pos] = output[src_pos]
                else:
                    output[out_pos] = 0
                out_pos += 1
                src_pos += 1
        else:
            # 字面量字节
            output[out_pos] = compressed_data[literal_pos]
            out_pos += 1
            literal_pos += 1
            remaining -= 1
        
        ctrl_word = (ctrl_word >> 1) & 0xFFFFFFFF
    
    return output[:output_size]


def decode_vtv(vtv_path: str, output_path: str = None):
    """
    解码VTV图像文件为BMP
    
    Args:
        vtv_path: VTV文件路径
        output_path: 输出BMP路径（默认同名.bmp）
    """
    if output_path is None:
        output_path = os.path.splitext(vtv_path)[0] + '.bmp'
    
    with open(vtv_path, 'rb') as f:
        data = bytearray(f.read())
    
    file_size = len(data)
    
    # 判断头部格式
    # 条件: [1]-[0]==0x18 && [2]==[1] && [3]-[0]==4
    has_ucat_header = (
        (data[1] - data[0]) & 0xFF == 0x18 and
        data[2] == data[1] and
        (data[3] - data[0]) & 0xFF == 0x04
    )
    
    if has_ucat_header:
        img_offset = 0xA8
        # XOR解密前4字节
        xor_key = [0x55, 0x43, 0x41, 0x54]
        for i in range(4):
            data[img_offset + i] ^= xor_key[i]
    else:
        img_offset = 0x10
    
    # 解析图片头
    width = struct.unpack_from('<H', data, img_offset)[0]
    height = struct.unpack_from('<H', data, img_offset + 2)[0]
    fmt = struct.unpack_from('<H', data, img_offset + 4)[0]
    
    fmt_high = (fmt >> 8) & 0xFF
    fmt_low = fmt & 0xFF
    is_16bit = (fmt & 0xFF00) == 0x300
    bpp = 16 if is_16bit else 32
    
    print(f"[*] 文件: {vtv_path} ({file_size:,} 字节)")
    print(f"[*] 头部类型: {'UCAT (偏移0xA8)' if has_ucat_header else '简单 (偏移0x10)'}")
    print(f"[*] 尺寸: {width}x{height}")
    print(f"[*] 格式: 0x{fmt:04X} ({bpp}位色, 压缩参数=0x{fmt_low:02X})")
    
    if width == 0 or height == 0 or width > 4096 or height > 4096:
        print(f"[!] 异常的尺寸，可能不是图片文件")
        return False
    
    # 计算输出大小
    output_size = width * height * 4
    if is_16bit:
        output_size //= 2
    
    print(f"[*] 解压输出大小: {output_size:,} 字节")
    
    # 压缩数据从 img_offset + 8 开始
    compressed_start = img_offset + 8
    compressed_data = bytes(data[compressed_start:])
    
    # 解压
    print(f"[*] 正在解压...")
    try:
        pixel_data = decompress_lzss(compressed_data, output_size, fmt_low)
    except Exception as e:
        print(f"[!] 解压失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print(f"[*] 解压完成，得到 {len(pixel_data):,} 字节")
    
    # 转换为BMP
    if is_16bit:
        # 16位色转24位BMP
        print(f"[*] 16位色模式，转换为24位BMP...")
        bmp_data = write_bmp_16bit(pixel_data, width, height)
    else:
        # 32位BGRA转24位BMP（丢弃alpha）或32位BMP（保留alpha）
        print(f"[*] 32位色模式，输出为32位BMP...")
        bmp_data = write_bmp_32bit(pixel_data, width, height)
    
    with open(output_path, 'wb') as f:
        f.write(bmp_data)
    
    print(f"[*] 输出: {output_path} ({len(bmp_data):,} 字节)")
    return True


def write_bmp_32bit(pixel_data: bytearray, width: int, height: int) -> bytes:
    """
    将BGRA像素数据写入32位BMP
    BMP是自底向上存储的，但游戏像素数据通常也是自底向上
    """
    row_size = width * 4  # 32位BMP每行已经4字节对齐
    pixel_size = row_size * height
    header_size = 14 + 40  # BMP file header + DIB header
    file_size = header_size + pixel_size
    
    buf = io.BytesIO()
    
    # BMP File Header (14 bytes)
    buf.write(b'BM')
    buf.write(struct.pack('<I', file_size))
    buf.write(struct.pack('<HH', 0, 0))
    buf.write(struct.pack('<I', header_size))
    
    # DIB Header - BITMAPINFOHEADER (40 bytes)
    buf.write(struct.pack('<I', 40))          # header size
    buf.write(struct.pack('<i', width))        # width
    buf.write(struct.pack('<i', height))       # height (正数=自底向上)
    buf.write(struct.pack('<H', 1))            # planes
    buf.write(struct.pack('<H', 32))           # bpp
    buf.write(struct.pack('<I', 0))            # compression (BI_RGB)
    buf.write(struct.pack('<I', pixel_size))   # image size
    buf.write(struct.pack('<i', 2835))         # X ppm
    buf.write(struct.pack('<i', 2835))         # Y ppm
    buf.write(struct.pack('<I', 0))            # colors used
    buf.write(struct.pack('<I', 0))            # important colors
    
    # 像素数据 - 游戏通常是自顶向下，BMP需要自底向上，所以翻转行序
    for y in range(height - 1, -1, -1):
        row_start = y * row_size
        row_end = row_start + row_size
        if row_end <= len(pixel_data):
            buf.write(pixel_data[row_start:row_end])
        else:
            buf.write(b'\x00' * row_size)
    
    return buf.getvalue()


def write_bmp_16bit(pixel_data: bytearray, width: int, height: int) -> bytes:
    """
    将16位色像素数据转换为24位BMP
    假设RGB565格式
    """
    row_size_24 = ((width * 3 + 3) // 4) * 4  # 24位BMP行对齐
    pixel_size = row_size_24 * height
    header_size = 14 + 40
    file_size = header_size + pixel_size
    
    buf = io.BytesIO()
    
    # BMP File Header
    buf.write(b'BM')
    buf.write(struct.pack('<I', file_size))
    buf.write(struct.pack('<HH', 0, 0))
    buf.write(struct.pack('<I', header_size))
    
    # DIB Header
    buf.write(struct.pack('<I', 40))
    buf.write(struct.pack('<i', width))
    buf.write(struct.pack('<i', height))
    buf.write(struct.pack('<H', 1))
    buf.write(struct.pack('<H', 24))
    buf.write(struct.pack('<I', 0))
    buf.write(struct.pack('<I', pixel_size))
    buf.write(struct.pack('<i', 2835))
    buf.write(struct.pack('<i', 2835))
    buf.write(struct.pack('<I', 0))
    buf.write(struct.pack('<I', 0))
    
    # 转换像素
    for y in range(height - 1, -1, -1):
        row_buf = bytearray(row_size_24)
        for x in range(width):
            src_off = (y * width + x) * 2
            if src_off + 1 < len(pixel_data):
                pixel = struct.unpack_from('<H', pixel_data, src_off)[0]
                r = ((pixel >> 11) & 0x1F) * 255 // 31
                g = ((pixel >> 5) & 0x3F) * 255 // 63
                b = (pixel & 0x1F) * 255 // 31
                row_buf[x * 3] = b
                row_buf[x * 3 + 1] = g
                row_buf[x * 3 + 2] = r
        buf.write(row_buf)
    
    return buf.getvalue()


def write_png_32bit(pixel_data: bytearray, width: int, height: int, output_path: str):
    """
    将BGRA像素数据写入PNG（如果有zlib可用）
    """
    import zlib
    
    # PNG使用RGBA，游戏数据是BGRA，需要交换R和B
    raw_rows = bytearray()
    row_size = width * 4
    for y in range(height):
        raw_rows.append(0)  # filter byte: None
        row_start = y * row_size
        for x in range(width):
            px_off = row_start + x * 4
            if px_off + 3 < len(pixel_data):
                b = pixel_data[px_off]
                g = pixel_data[px_off + 1]
                r = pixel_data[px_off + 2]
                a = pixel_data[px_off + 3]
                raw_rows.extend([r, g, b, a])
            else:
                raw_rows.extend([0, 0, 0, 255])
    
    def make_chunk(chunk_type, data):
        chunk = chunk_type + data
        crc = zlib.crc32(chunk) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + chunk + struct.pack('>I', crc)
    
    with open(output_path, 'wb') as f:
        # PNG signature
        f.write(b'\x89PNG\r\n\x1a\n')
        
        # IHDR
        ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
        f.write(make_chunk(b'IHDR', ihdr_data))
        
        # IDAT
        compressed = zlib.compress(bytes(raw_rows), 9)
        f.write(make_chunk(b'IDAT', compressed))
        
        # IEND
        f.write(make_chunk(b'IEND', b''))


def batch_decode(input_dir: str, output_dir: str, fmt: str = 'bmp'):
    """批量解码VTV文件"""
    os.makedirs(output_dir, exist_ok=True)
    
    vtv_files = [f for f in os.listdir(input_dir) if f.lower().endswith('.vtv')]
    vtv_files.sort()
    
    print(f"[*] 找到 {len(vtv_files)} 个VTV文件")
    
    success = 0
    failed = 0
    
    for fname in vtv_files:
        vtv_path = os.path.join(input_dir, fname)
        out_name = os.path.splitext(fname)[0] + f'.{fmt}'
        out_path = os.path.join(output_dir, out_name)
        
        try:
            if decode_vtv(vtv_path, out_path):
                success += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[!] {fname}: {e}")
            failed += 1
        print()
    
    print(f"[*] 批量完成: 成功={success}, 失败={failed}, 总计={len(vtv_files)}")


def main():
    if len(sys.argv) < 2:
        print("Interlude Engine VTV 图像解码工具")
        print()
        print("用法:")
        print(f"  python {sys.argv[0]} <file.vtv> [output.bmp]     # 单个文件")
        print(f"  python {sys.argv[0]} -batch <vtv目录> [输出目录]   # 批量解码")
        print()
        print("示例:")
        print(f"  python {sys.argv[0]} ABG001B.VTV")
        print(f"  python {sys.argv[0]} ABG001B.VTV output.bmp")
        print(f"  python {sys.argv[0]} -batch unpacked/ decoded/")
        sys.exit(1)
    
    if sys.argv[1] == '-batch':
        input_dir = sys.argv[2] if len(sys.argv) > 2 else '.'
        output_dir = sys.argv[3] if len(sys.argv) > 3 else 'vtv_decoded'
        batch_decode(input_dir, output_dir)
    else:
        vtv_path = sys.argv[1]
        out_path = sys.argv[2] if len(sys.argv) > 2 else None
        decode_vtv(vtv_path, out_path)


if __name__ == '__main__':
    main()
