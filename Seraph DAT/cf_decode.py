#!/usr/bin/env python3
"""
Seraph Engine - CF/CT/CB/CC Image Decoder
Game: WAGAMAJO (わがまま女にもほどがある)
Engine: Seraph (seraph.exe / Selaphim)

CF format header (0x10 bytes):
  0x00  2B  signature   "CF" (0x4643)
  0x02  2B  unk/version 0
  0x04  2B  x_offset
  0x06  2B  y_offset
  0x08  2B  width
  0x0A  2B  height
  0x0C  4B  data_size   compressed data size (= filesize - 16)

  0x10  ...  compressed data (custom LZ scheme)

Compression: Custom bytecode-based scheme with:
  - Literal copy (raw bytes from stream)
  - RLE (fill single byte)
  - Row-relative back-references (1/2/4 rows back, pixel-aligned)
  - Pixel-aligned pattern copy (3-byte or 6-byte patterns)
  - Byte-level back-references (arbitrary offset)

Pixel format: 24bpp BGR, top-down, no row padding
"""

import struct
import sys
import os
import argparse
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    Image = None


def decompress_cf(src: bytes, width: int, height: int) -> bytearray:
    """
    Decompress CF image data (FUN_004037e0).
    
    Global state mapping:
      DAT_00432274 = data_size (input size limit)
      DAT_00432270 = src base pointer (iVar16 in loop = DAT_00432270)
      DAT_00432284 = src read position (si)
      DAT_00432288 = dst base pointer (iVar14 in loop = DAT_00432288)
      DAT_00432290 = dst write position (di)
      DAT_0043228c = width
      DAT_00432278 = height
    
    Output size = height * width * 3 (but buffer allocated (height+1)*width*3)
    """
    out_size = height * width * 3
    out = bytearray(out_size + width * 3)  # extra row for safety
    stride = width * 3  # bytes per row
    
    si = 0       # source index
    di = 0       # dest index
    data_len = len(src)
    
    while di < out_size and si < data_len:
        b = src[si]
        
        # 0xF0 mask = end marker
        if (b & 0xF0) == 0xF0:
            break
        
        if (b & 0x80) == 0:
            # High bit clear
            if (b & 0x40) == 0:
                # 00xx_xxxx: Literal copy
                # length = (b & 0x3F) + 1
                n = (b & 0x3F) + 1
                si += 1
                out[di:di+n] = src[si:si+n]
                si += n
                di += n
            else:
                # 01xx_xxxx: RLE fill single byte
                # count = (b & 0x3F) + 2
                n = (b & 0x3F) + 2
                si += 1
                val = src[si]
                si += 1
                for j in range(n):
                    out[di + j] = val
                di += n
        elif (b & 0x40) == 0:
            # 10xx_xxxx: 2-byte commands
            # bits [5:4] = sub-command (0..3)
            sub = (b >> 4) & 3
            si2 = si + 1
            ext = (b & 0x0F) * 0x100 + src[si2]
            si += 2
            
            if sub == 0:
                # RLE fill (same as 01xx but with larger count)
                n = ext + 2
                val = src[si]
                si += 1
                for j in range(n):
                    out[di + j] = val
                di += n
            elif sub == 1:
                # Copy from 1 row above (stride = width*3)
                n = ext + 1
                ref = di - stride
                for j in range(n):
                    out[di + j] = out[ref + j]
                di += n
            elif sub == 2:
                # Copy from 2 rows above (stride*2)
                n = ext + 1
                ref = di - stride * 2
                for j in range(n):
                    out[di + j] = out[ref + j]
                di += n
            elif sub == 3:
                # Copy from 4 rows above (stride*4)
                n = ext + 1
                ref = di - stride * 4
                for j in range(n):
                    out[di + j] = out[ref + j]
                di += n
        elif (b & 0x30) == 0:
            # 1100_xxxx: Pixel-aligned pattern repeat
            # bit3 selects 3-byte or 6-byte pixel unit
            si2 = si + 1
            ext = (b & 0x07) * 0x100 + src[si2]
            si += 2
            count = ext + 2  # repeat count
            
            if ((b >> 3) & 1) == 0:
                # 3-byte pixel pattern
                pat = src[si:si+3]
                si += 3
                for j in range(count):
                    out[di:di+3] = pat
                    di += 3
            else:
                # 6-byte pixel pattern (2 pixels)
                pat = src[si:si+6]
                si += 6
                for j in range(count):
                    out[di:di+6] = pat
                    di += 6
        elif (b & 0x20) == 0:
            # 1101_xxxx: Pixel-aligned back-reference (3-byte units)
            si2 = si + 1
            offset_val = (b & 0x0F) * 0x100 + src[si2]
            length = src[si + 2] + 1
            si += 3
            ref = di - (offset_val * 3 + 3)
            for j in range(length):
                out[di:di+3] = out[ref:ref+3]
                di += 3
                ref += 3
        else:
            # 1110_xxxx: Byte-level back-reference
            si2 = si + 1
            offset_val = (b & 0x0F) * 0x100 + src[si2]
            n = src[si + 2] + 1
            si += 3
            ref = di - offset_val - 1
            for j in range(n):
                out[di + j] = out[ref + j]
            di += n
    
    return out[:out_size]


def decode_cf(filepath: str) -> tuple:
    """
    Decode a .cf file. Returns (width, height, bgr_pixels, x_off, y_off).
    """
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if len(data) < 16:
        raise ValueError("File too small for CF header")
    
    sig = data[0:2]
    if sig != b'CF':
        raise ValueError(f"Not a CF file (signature: {sig!r})")
    
    unk, x_off, y_off, width, height, data_size = struct.unpack_from('<HHHHHI', data, 2)
    
    if data_size + 16 > len(data):
        print(f"Warning: data_size({data_size}) + 16 > file_size({len(data)})")
        data_size = len(data) - 16
    
    compressed = data[16:16 + data_size]
    pixels = decompress_cf(compressed, width, height)
    
    expected = width * height * 3
    if len(pixels) != expected:
        print(f"Warning: decompressed {len(pixels)} bytes, expected {expected}")
    
    return width, height, pixels, x_off, y_off


def bgr_to_rgb(bgr_data: bytearray, width: int, height: int) -> bytearray:
    """Swap B and R channels for PNG output."""
    rgb = bytearray(len(bgr_data))
    for i in range(0, len(bgr_data), 3):
        rgb[i] = bgr_data[i + 2]      # R
        rgb[i + 1] = bgr_data[i + 1]  # G
        rgb[i + 2] = bgr_data[i]      # B
    return rgb


def save_png(filepath: str, width: int, height: int, bgr_data: bytearray):
    """Save as PNG using PIL."""
    if Image is None:
        raise RuntimeError("Pillow not installed. Run: pip install Pillow")
    
    rgb = bgr_to_rgb(bgr_data, width, height)
    img = Image.frombytes('RGB', (width, height), bytes(rgb))
    img.save(filepath)
    print(f"Saved: {filepath} ({width}x{height})")


def save_raw_bmp(filepath: str, width: int, height: int, bgr_data: bytearray):
    """Save as BMP without PIL dependency."""
    row_stride = ((width * 3 + 3) // 4) * 4
    pad = row_stride - width * 3
    pixel_size = row_stride * height
    file_size = 54 + pixel_size
    
    with open(filepath, 'wb') as f:
        # BMP header
        f.write(b'BM')
        f.write(struct.pack('<I', file_size))
        f.write(struct.pack('<HH', 0, 0))
        f.write(struct.pack('<I', 54))
        # DIB header
        f.write(struct.pack('<I', 40))
        f.write(struct.pack('<i', width))
        f.write(struct.pack('<i', -height))  # negative = top-down
        f.write(struct.pack('<HH', 1, 24))
        f.write(struct.pack('<I', 0))  # no compression
        f.write(struct.pack('<I', pixel_size))
        f.write(struct.pack('<ii', 2835, 2835))
        f.write(struct.pack('<II', 0, 0))
        # pixel data (already BGR top-down, just add padding)
        for y in range(height):
            row_off = y * width * 3
            f.write(bgr_data[row_off:row_off + width * 3])
            if pad:
                f.write(b'\x00' * pad)
    
    print(f"Saved: {filepath} ({width}x{height})")


def main():
    parser = argparse.ArgumentParser(description='Seraph Engine CF Image Decoder')
    parser.add_argument('input', help='Input .cf file or directory')
    parser.add_argument('-o', '--output', help='Output file/directory')
    parser.add_argument('-b', '--batch', action='store_true', help='Batch decode directory')
    parser.add_argument('--bmp', action='store_true', help='Save as BMP instead of PNG')
    parser.add_argument('--info', action='store_true', help='Show header info only')
    args = parser.parse_args()
    
    if args.batch:
        input_dir = Path(args.input)
        output_dir = Path(args.output) if args.output else input_dir / 'decoded'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        files = sorted(input_dir.glob('*.cf'))
        if not files:
            print(f"No .cf files found in {input_dir}")
            return
        
        success = 0
        for fp in files:
            try:
                w, h, pixels, xo, yo = decode_cf(str(fp))
                ext = '.bmp' if args.bmp else '.png'
                out_path = output_dir / (fp.stem + ext)
                if args.bmp:
                    save_raw_bmp(str(out_path), w, h, pixels)
                else:
                    save_png(str(out_path), w, h, pixels)
                success += 1
            except Exception as e:
                print(f"FAILED: {fp.name}: {e}")
        
        print(f"\nBatch complete: {success}/{len(files)} files decoded")
    
    elif args.info:
        with open(args.input, 'rb') as f:
            hdr = f.read(16)
        sig, unk, x_off, y_off, w, h, data_sz = struct.unpack('<2sHHHHHI', hdr)
        file_sz = os.path.getsize(args.input)
        print(f"File:      {args.input}")
        print(f"Signature: {sig}")
        print(f"Unknown:   0x{unk:04X}")
        print(f"Offset:    ({x_off}, {y_off})")
        print(f"Size:      {w} x {h}")
        print(f"Data size: {data_sz} (file: {file_sz}, header: 16)")
        print(f"Raw 24bpp: {w*h*3}")
        print(f"Ratio:     {data_sz/(w*h*3)*100:.1f}%")
    
    else:
        w, h, pixels, xo, yo = decode_cf(args.input)
        
        if args.output:
            out_path = args.output
        else:
            out_path = Path(args.input).with_suffix('.bmp' if args.bmp else '.png')
        
        if args.bmp:
            save_raw_bmp(str(out_path), w, h, pixels)
        else:
            save_png(str(out_path), w, h, pixels)


if __name__ == '__main__':
    main()
