#!/usr/bin/env python3
"""
EMI (EMSAC-Image-2) → PNG 解码器
适用引擎: EntisGLS / VIST (EScriptV2)
支持: ERI_RUNLENGTH_GAMMA 编码 (coding=0x01), architecture=-1, 8/24/32bpp

用法:
  python emi2png.py <input.emi> [output.png]
  python emi2png.py <input_dir> [output_dir]    (批量转换)

如存在 eri_fast.so/dll 则自动使用C加速 (~60x)，否则回退纯Python。
编译: gcc -O2 -shared -fPIC -o eri_fast.so eri_fast.c
"""

import struct
import sys
import os
import array
import ctypes
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("需要 Pillow: pip install Pillow")
    sys.exit(1)


# ─── Try loading C acceleration ───

_clib = None

def _load_clib():
    global _clib
    if _clib is not None:
        return _clib
    for name in ['eri_fast.so', 'eri_fast.dll', 'eri_fast.dylib']:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
        if os.path.exists(p):
            try:
                lib = ctypes.CDLL(p)
                lib.decode_eri_gamma_c.argtypes = [
                    ctypes.c_char_p, ctypes.c_int,
                    ctypes.POINTER(ctypes.c_int32), ctypes.c_int]
                lib.decode_eri_gamma_c.restype = ctypes.c_int
                lib.reconstruct_pixels_c.argtypes = [
                    ctypes.POINTER(ctypes.c_int32), ctypes.c_char_p,
                    ctypes.c_int, ctypes.c_int, ctypes.c_int]
                lib.reconstruct_pixels_c.restype = None
                lib.bgr_flip_to_rgb.argtypes = [
                    ctypes.c_char_p, ctypes.c_char_p,
                    ctypes.c_int, ctypes.c_int, ctypes.c_int]
                lib.bgr_flip_to_rgb.restype = None
                _clib = lib
                return lib
            except Exception:
                pass
    _clib = False
    return False


# ─── Pure Python fallback ───

class BitReader:
    __slots__ = ('data', 'pos', 'bits_left', 'buffer')

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.bits_left = 0
        self.buffer = 0
        self._fill()

    def _fill(self):
        if self.pos + 4 <= len(self.data):
            w = struct.unpack_from('<I', self.data, self.pos)[0]
            self.pos += 4
        else:
            remaining = self.data[self.pos:self.pos+4]
            remaining = remaining + b'\x00' * (4 - len(remaining))
            w = struct.unpack_from('<I', remaining, 0)[0]
            self.pos = min(self.pos + 4, len(self.data))
        self.buffer = ((w >> 24) & 0xFF) | ((w >> 8) & 0xFF00) | \
                      ((w << 8) & 0xFF0000) | ((w << 24) & 0xFF000000)
        self.bits_left = 32

    def get_bit(self):
        bit = (self.buffer >> 31) & 1
        self.buffer = (self.buffer << 1) & 0xFFFFFFFF
        self.bits_left -= 1
        if self.bits_left == 0:
            self._fill()
        return bit

    def read_gamma(self):
        value = 0
        base = 2
        while True:
            bit = (self.buffer >> 31) & 1
            self.buffer = (self.buffer << 1) & 0xFFFFFFFF
            self.bits_left -= 1
            if self.bits_left == 0:
                self._fill()
            if bit == 0:
                final_bit = (self.buffer >> 31) & 1
                self.buffer = (self.buffer << 1) & 0xFFFFFFFF
                self.bits_left -= 1
                if self.bits_left == 0:
                    self._fill()
                return value * 2 + final_bit + base - 1
            else:
                data_bit = (self.buffer >> 31) & 1
                self.buffer = (self.buffer << 1) & 0xFFFFFFFF
                self.bits_left -= 1
                if self.bits_left == 0:
                    self._fill()
                value = value * 2 + data_bit
                base *= 2


def _decode_gamma_py(data, count):
    reader = BitReader(data)
    output = array.array('i', [0]) * count
    out_pos = 0
    phase = bool(reader.get_bit())
    while out_pos < count:
        if phase:
            n = reader.read_gamma()
            end = min(out_pos + n, count)
            while out_pos < end:
                s = reader.get_bit()
                m = reader.read_gamma()
                output[out_pos] = -m if s else m
                out_pos += 1
        else:
            n = reader.read_gamma()
            out_pos = min(out_pos + n, count)
        phase = not phase
    return output


def _reconstruct_py(coefficients, width, height, channels):
    stride = width * channels
    pixels = bytearray(height * stride)
    for ch in range(channels):
        acc = 0
        for x in range(width):
            acc = (acc + coefficients[ch * width + x]) & 0xFF
            pixels[x * channels + ch] = acc
        for y in range(1, height):
            acc = 0
            for x in range(width):
                ci = y * stride + ch * width + x
                above = pixels[(y-1) * stride + x * channels + ch]
                acc = (acc + coefficients[ci]) & 0xFF
                pixels[y * stride + x * channels + ch] = (above + acc) & 0xFF
    return pixels


def _bgr_flip_py(pixels, width, height, channels):
    stride = width * channels
    if channels == 3:
        out = bytearray(width * height * 3)
        for y in range(height):
            sy = height - 1 - y
            so = sy * stride
            do = y * width * 3
            for x in range(width):
                si = so + x * 3
                di = do + x * 3
                out[di] = pixels[si+2]
                out[di+1] = pixels[si+1]
                out[di+2] = pixels[si]
        return out
    elif channels == 4:
        out = bytearray(width * height * 4)
        for y in range(height):
            sy = height - 1 - y
            so = sy * stride
            do = y * width * 4
            for x in range(width):
                si = so + x * 4
                di = do + x * 4
                out[di] = pixels[si+2]
                out[di+1] = pixels[si+1]
                out[di+2] = pixels[si]
                out[di+3] = pixels[si+3]
        return out
    else:
        out = bytearray(width * height)
        for y in range(height):
            sy = height - 1 - y
            out[y*width:(y+1)*width] = pixels[sy*width:(sy+1)*width]
        return out


# ─── EMI Parser ───

def parse_emi(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    if data[0:4] != b'VIST':
        raise ValueError(f"Not a valid EMI file: {data[0:4]}")
    pos = 0x40
    info = {}
    comp = None
    while pos < len(data) - 16:
        tag = data[pos:pos+8].rstrip(b'\x00').decode('ascii')
        size = struct.unpack_from('<Q', data, pos+8)[0]
        ss = pos + 16
        if tag.startswith('Header'):
            sp = ss
            se = ss + size
            while sp < se:
                st = data[sp:sp+8].rstrip(b'\x00').decode('ascii')
                sz = struct.unpack_from('<Q', data, sp+8)[0]
                sd = data[sp+16:sp+16+sz]
                if st.startswith('ImageInf'):
                    xf = struct.unpack_from('<I', sd, 4)[0]
                    info = {
                        'version': struct.unpack_from('<I', sd, 0)[0],
                        'transformation': xf,
                        'coding': (xf >> 16) & 0xFF,
                        'format_type': (xf >> 24) & 0xFF,
                        'architecture': struct.unpack_from('<i', sd, 8)[0],
                        'width': struct.unpack_from('<I', sd, 16)[0],
                        'height': struct.unpack_from('<I', sd, 20)[0],
                        'bpp': struct.unpack_from('<I', sd, 24)[0],
                    }
                sp += 16 + sz
        elif tag.startswith('Stream'):
            st2 = data[ss:ss+8].rstrip(b'\x00').decode('ascii')
            sz2 = struct.unpack_from('<Q', data, ss+8)[0]
            comp = data[ss+16:ss+16+sz2]
        pos = ss + size
    return info, comp


# ─── Main Decode ───

def decode_emi(filepath):
    info, comp = parse_emi(filepath)
    w, h, bpp = info['width'], info['height'], info['bpp']
    ch = bpp // 8
    if ch not in (1, 3, 4):
        raise ValueError(f"Unsupported bpp: {bpp}")
    if info['coding'] != 1:
        raise ValueError(f"Unsupported coding: {info['coding']}")
    total = w * h * ch

    lib = _load_clib()

    if lib:
        # C accelerated path
        coeffs = (ctypes.c_int32 * total)()
        lib.decode_eri_gamma_c(comp, len(comp), coeffs, total)
        pixels = ctypes.create_string_buffer(total)
        lib.reconstruct_pixels_c(coeffs, pixels, w, h, ch)
        out = ctypes.create_string_buffer(total)
        lib.bgr_flip_to_rgb(pixels, out, w, h, ch)
        mode = {1: 'L', 3: 'RGB', 4: 'RGBA'}[ch]
        return Image.frombytes(mode, (w, h), out.raw)
    else:
        # Pure Python fallback
        coefficients = _decode_gamma_py(comp, total)
        pixels = _reconstruct_py(coefficients, w, h, ch)
        out = _bgr_flip_py(pixels, w, h, ch)
        mode = {1: 'L', 3: 'RGB', 4: 'RGBA'}[ch]
        return Image.frombytes(mode, (w, h), bytes(out))


def convert_file(input_path, output_path=None):
    if output_path is None:
        output_path = os.path.splitext(input_path)[0] + '.png'
    info, _ = parse_emi(input_path)
    img = decode_emi(input_path)
    img.save(output_path)
    print(f"  {os.path.basename(input_path)}: {info['width']}x{info['height']} "
          f"{info['bpp']}bpp → {os.path.basename(output_path)}")


def main():
    if len(sys.argv) < 2:
        print("EMI (EMSAC-Image-2) → PNG 解码器")
        print("适用引擎: EntisGLS / VIST")
        print()
        print(f"用法:")
        print(f"  {sys.argv[0]} <input.emi> [output.png]")
        print(f"  {sys.argv[0]} <input_dir> [output_dir]  (批量)")
        sys.exit(1)

    lib = _load_clib()
    print(f"加速: {'C (eri_fast.so)' if lib else '纯Python (慢)'}")

    path = sys.argv[1]
    if os.path.isdir(path):
        outdir = sys.argv[2] if len(sys.argv) > 2 else path
        os.makedirs(outdir, exist_ok=True)
        files = sorted(Path(path).glob('*.emi'))
        print(f"批量转换: {len(files)} 个文件")
        ok = 0
        for f in files:
            try:
                convert_file(str(f), os.path.join(outdir, f.stem + '.png'))
                ok += 1
            except Exception as e:
                print(f"  ✗ {f.name}: {e}")
        print(f"完成: {ok}/{len(files)}")
    else:
        out = sys.argv[2] if len(sys.argv) > 2 else None
        convert_file(path, out)


if __name__ == '__main__':
    main()
