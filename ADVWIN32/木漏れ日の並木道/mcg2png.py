#!/usr/bin/env python3
"""
mcg2png.py - ADVWIN32 MCG image decoder
Engine: ADVWIN32 (木漏れ日の並木道 / Komorebi no Namikimichi)
Format: MCG 1.01 - ROL1+XOR stream cipher + LZSS (4K window) compressed BGR image

Encryption: Each byte is ROL(byte,1) XOR running_key, where running_key starts
from a seed and is incremented by (loop_counter & 0xFF) each byte. The loop
counter decrements from (data_size-1) to 0, so the increment changes every byte.

Compression: Standard LZSS with 4096-byte window, initial write position 0xFEE,
flag byte LSB-first, bit=1 literal, bit=0 back-reference (12-bit offset + 4-bit length + 3).

Usage:
    python mcg2png.py <input.mcg> [output.png] [-k KEY]
    python mcg2png.py -b <directory> [-k KEY]
    python mcg2png.py --bruteforce <input.mcg>

Key for 木漏れ日の並木道: 0x7B (default)
"""

import struct, sys, os, argparse
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow required. pip install Pillow"); sys.exit(1)


def parse_mcg_header(data):
    if len(data) < 0x40 or data[:8] != b'MCG 1.01':
        raise ValueError(f"Not a MCG 1.01 file")
    return {
        'data_offset': struct.unpack_from('<I', data, 0x10)[0],
        'width':       struct.unpack_from('<I', data, 0x1C)[0],
        'height':      struct.unpack_from('<I', data, 0x20)[0],
        'bpp':         struct.unpack_from('<I', data, 0x24)[0],
        'raw_size':    struct.unpack_from('<I', data, 0x28)[0],
    }


def mcg_decrypt(data, key_seed, count):
    """In-place MCG decryption. Key byte advances by (ecx & 0xFF) where ecx decrements each iteration."""
    if key_seed == 0:
        return
    bl = key_seed & 0xFF
    ecx = count
    for i in range(count):
        cl = ecx & 0xFF
        b = data[i]
        al = ((b << 1) | (b >> 7)) & 0xFF
        al ^= bl
        bl = (bl + cl) & 0xFF
        data[i] = al
        ecx -= 1


def lzss_decompress(src, max_output):
    """LZSS: 4KB window, init pos 0xFEE, flag LSB-first, bit1=literal, bit0=backref."""
    window = bytearray(4096)
    wpos = 0xFEE
    out = bytearray()
    si = 0; end = len(src)
    while si < end and len(out) < max_output:
        flags = src[si] | 0xFF00; si += 1
        while flags & 0x100:
            if si >= end or len(out) >= max_output: return out
            if flags & 1:
                b = src[si]; si += 1
                window[wpos & 0xFFF] = b; wpos += 1; out.append(b)
            else:
                if si + 1 >= end: return out
                lo = src[si]; si += 1
                hi = src[si]; si += 1
                offset = lo | ((hi & 0x0F) << 8)
                length = (hi >> 4) + 3
                for _ in range(length):
                    if len(out) >= max_output: return out
                    b = window[offset & 0xFFF]; offset += 1
                    window[wpos & 0xFFF] = b; wpos += 1; out.append(b)
            flags >>= 1
    return out


def mcg_to_image(mcg_data, key_seed=0x7B):
    hdr = parse_mcg_header(mcg_data)
    if hdr['bpp'] != 24:
        raise ValueError(f"Only 24bpp supported (got {hdr['bpp']})")
    w, h, raw_size = hdr['width'], hdr['height'], hdr['raw_size']
    enc = bytearray(mcg_data[hdr['data_offset']:])
    mcg_decrypt(enc, key_seed, len(enc) - 1)
    pixels = lzss_decompress(bytes(enc), raw_size)
    if len(pixels) != raw_size:
        raise ValueError(f"Size mismatch: {len(pixels)} vs {raw_size}. Wrong key 0x{key_seed:02X}?")
    stride = w * 3
    img = Image.new('RGB', (w, h))
    px = img.load()
    for y in range(h):
        ro = y * stride
        for x in range(w):
            o = ro + x * 3
            px[x, y] = (pixels[o+2], pixels[o+1], pixels[o])
    return img


def bruteforce_key(mcg_data):
    hdr = parse_mcg_header(mcg_data)
    raw_size = hdr['raw_size']
    enc_orig = mcg_data[hdr['data_offset']:]
    for seed in range(256):
        enc = bytearray(enc_orig)
        mcg_decrypt(enc, seed, len(enc) - 1)
        px = lzss_decompress(bytes(enc), raw_size + 1)
        if len(px) == raw_size:
            return seed
    return -1


def convert_file(inp, out=None, key=0x7B):
    if out is None: out = os.path.splitext(inp)[0] + '.png'
    try:
        with open(inp, 'rb') as f: d = f.read()
        img = mcg_to_image(d, key)
        img.save(out)
        print(f"  {os.path.basename(inp)} -> {os.path.basename(out)} ({img.width}x{img.height})")
        return True
    except Exception as e:
        print(f"  {os.path.basename(inp)}: ERROR - {e}")
        return False


def main():
    ap = argparse.ArgumentParser(description='ADVWIN32 MCG image decoder')
    ap.add_argument('input', nargs='?')
    ap.add_argument('output', nargs='?')
    ap.add_argument('-k', '--key', type=lambda x: int(x, 0), default=0x7B)
    ap.add_argument('-b', '--batch', action='store_true')
    ap.add_argument('--bruteforce', action='store_true')
    a = ap.parse_args()
    if not a.input: ap.print_help(); return
    if a.bruteforce:
        with open(a.input, 'rb') as f: d = f.read()
        print(f"Bruteforcing key for {a.input}...")
        k = bruteforce_key(d)
        print(f"Found key: 0x{k:02X}" if k >= 0 else "No valid key found!")
        return
    if a.batch:
        fs = sorted(Path(a.input).glob('*.[Mm][Cc][Gg]'))
        if not fs: print("No MCG files found"); return
        print(f"Converting {len(fs)} files (key=0x{a.key:02X})...")
        ok = sum(1 for f in fs if convert_file(str(f), key=a.key))
        print(f"Done: {ok}/{len(fs)}")
    else:
        convert_file(a.input, a.output, a.key)


if __name__ == '__main__':
    main()
