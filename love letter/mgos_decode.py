#!/usr/bin/env python3
"""
MGOS (MU Game Operation System) BMP Decoder - Pure Python
Supports: Fd, Fc(?), 8P(?), BM formats
Reverse engineered from loveletter.exe (0x4217E0, 0x423A10)

Usage:
    python mgos_decode.py input.bmp [output.png]
    python mgos_decode.py --batch input_dir/ [output_dir/]
"""
import struct, sys, os
from pathlib import Path

# === Huffman bit-reader lookup tables (from exe 0x4217E0) ===
T838 = bytes.fromhex("00070607050706070407060705070607030706070507060704070607050706070207060705070607040706070507060703070607050706070407060705070607010706070507060704070607050706070307060705070607040706070507060702070607050706070407060705070607030706070507060704070607050706070007060705070607040706070507060703070607050706070407060705070607020706070507060704070607050706070307060705070607040706070507060701070607050706070407060705070607030706070507060704070607050706070207060705070607040706070507060703070607050706070407060705070607")
TB40 = bytes.fromhex("00020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40424446484a4c4e50525456585a5c5e60626466686a6c6e70727476787a7c7e80828486888a8c8e90929496989a9c9ea0a2a4a6a8aaacaeb0b2b4b6b8babcbec0c2c4c6c8caccced0d2d4d6d8dadcdee0e2e4e6e8eaeceef0f2f4f6f8fafcfe0004080c1014181c2024282c3034383c4044484c5054585c6064686c7074787c8084888c9094989ca0a4a8acb0b4b8bcc0c4c8ccd0d4d8dce0e4e8ecf0f4f8fc0008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f800102030405060708090a0b0c0d0e0f00020406080a0c0e0004080c000800000")
TC40 = bytes.fromhex("01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f41434547494b4d4f51535557595b5d5f61636567696b6d6f71737577797b7d7f81838587898b8d8f91939597999b9d9fa1a3a5a7a9abadafb1b3b5b7b9bbbdbfc1c3c5c7c9cbcdcfd1d3d5d7d9dbdddfe1e3e5e7e9ebedeff1f3f5f7f9fbfdff02060a0e12161a1e22262a2e32363a3e42464a4e52565a5e62666a6e72767a7e82868a8e92969a9ea2a6aaaeb2b6babec2c6caced2d6dadee2e6eaeef2f6fafe040c141c242c343c444c545c646c747c848c949ca4acb4bcc4ccd4dce4ecf4fc08182838485868788898a8b8c8d8e8f81030507090b0d0f02060a0e040c08000")
TD40 = bytes.fromhex("01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404050505050505050506060606070708")
TE40 = bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030304040404040404040505050506060708")

INIT_TABLE = [2,1,0,3,4,5,10,11,12,13,14,15,22,23,24,25,26,27,28,29,
              6,8,7,9,16,17,18,19,20,21,30,31,32,33,34,35,36,37]
DELTA_MUL = [0,-1,-1,-1,-2,0,-3,0,-4,0,-5,0,-6,0,-7,0,-8,0]
DELTA_ADD = [-1,0,1,-1,0,-2,0,-3,0,-4,0,-5,0,-6,0,-7,0,-8]

def _s32(v):
    """Interpret uint32 as signed int32."""
    return v - 0x100000000 if v >= 0x80000000 else v

def _sar(v, n):
    """Arithmetic shift right for 32-bit."""
    s = _s32(v & 0xFFFFFFFF)
    return s >> n


class FdDecoder:
    def __init__(self, data):
        self.data = data
        self.bpp = data[2]
        self.width = struct.unpack_from('<H', data, 4)[0]
        self.height = struct.unpack_from('<H', data, 6)[0]
        self.pos = 16  # past header
        self.state = 0x80

        # Symbol lookup table (at 0x466798 in exe, indexed by read_value result)
        self.sym = [0] * 42
        for i in range(38):
            if i == 1:
                self.sym[3] = 38
            else:
                self.sym[INIT_TABLE[i] + 2] = i

        # Delta offset table for sym 2..19 (at 0x466f38, indexed by sym)
        self.dt = [0, 0] + [DELTA_MUL[i] * self.width + DELTA_ADD[i] for i in range(18)]

        # RLE delta offset for sym 0x14..0x25 (at 0x466ef0, offset so [0x14] maps to dt[2])
        # 0x466ef0 + sym*4 = 0x466f40 + (sym-0x14)*4 when sym >= 0x14
        # So rle_delta[sym] = dt[sym - 0x14 + 2] = dt[sym - 18]
        # But we need the table at 0x466ef0 which has 0x14 zero entries then delta_offsets
        self.rle_delta = [0] * 40
        for i in range(18):
            self.rle_delta[0x14 + i] = DELTA_MUL[i] * self.width + DELTA_ADD[i]

    def _rb(self):
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_value(self):
        """Read one Huffman-coded value from the bitstream.
        Exact translation of the pattern at 0x423aba-0x423b74."""
        # Phase 1: consume prefix bits from current state
        a = self.state & 0xFF
        ecx = TD40[a]
        al = TB40[a]
        self.state = al

        if al == 0:
            # Need more input bytes
            while True:
                nb = self._rb()
                self.state = nb
                edi = nb & 0xFF
                ecx += TE40[edi]
                if TC40[edi]:
                    self.state = TC40[edi]
                    break

        # Phase 2: extract value from accumulated bits
        a = self.state & 0xFF
        consumed = T838[a]
        eax = a + 0x100
        rem = ecx - consumed

        if rem > 0:
            eax = (eax << consumed) & 0xFFFFFF00
            nb = self._rb()
            eax = (eax + nb) & 0xFFFFFFFF
            rem -= 1
            if rem >= 8:
                nf = rem >> 3
                rem -= nf * 8
                for _ in range(nf):
                    nb = self._rb()
                    eax = ((nb + eax) << 8) & 0xFFFFFFFF
            eax = (eax * 2 + 1) & 0xFFFFFFFF
            sh = rem
        else:
            sh = ecx  # KEY: use original total bits, not remainder

        eax = (eax << (sh & 0x1F)) & 0xFFFFFFFF
        self.state = eax & 0xFF
        return _sar(eax, 8)

    def _read_signed_delta(self, shift):
        """Read a delta value with sign encoding. Used for pixel channel deltas."""
        v = self.read_value()
        raw = (v - 2) & 0xFFFFFFFF
        sign = (-(v & 1)) & 0xFFFFFFFF
        d = ((sign << shift) ^ (raw << shift)) & 0xFFFFFFFF
        return _s32(d)

    def decode(self):
        w, h = self.width, self.height
        n = w * h
        out = [0] * n
        op = 0

        try:
            while op < n:
                raw = self.read_value()
                sym = self.sym[raw] if 0 <= raw < len(self.sym) else 0

                if sym < 0x14:
                    if sym < 2:
                        # === LITERAL PIXEL ===
                        a = self.state & 0xFF
                        b0, b1, b2 = self._rb(), self._rb(), self._rb()
                        edx = (((b0 << 8 | b1) << 8 | b2) << 8) ^ 0x80000080
                        edx &= 0xFFFFFFFF
                        edx >>= T838[a]
                        eax = ((a << 16) & 0xFFFF0000) ^ ((edx >> 8) & 0xFFFFFF)
                        out[op] = eax & 0xFFFFFFFF
                        self.state = edx & 0xFF
                        op += 1
                    else:
                        # === DELTA REFERENCE (sym 2..19) ===
                        doff = self.dt[sym] if sym < len(self.dt) else 0
                        ref = op + doff
                        ebp = out[ref] if 0 <= ref < n else 0

                        # 3 channel deltas: shift 15, shift 7, shift 0 (with sar 1)
                        ebp = (ebp + self._read_signed_delta(15)) & 0xFFFFFFFF
                        ebp = (ebp + self._read_signed_delta(7)) & 0xFFFFFFFF

                        v3 = self.read_value()
                        raw3 = (v3 - 2) & 0xFFFFFFFF
                        s3 = (-(v3 & 1)) & 0xFFFFFFFF
                        ch3 = _s32((s3 ^ raw3) & 0xFFFFFFFF)
                        # cdq; sub eax,edx; sar eax,1 = divide by 2 toward zero
                        if ch3 < 0:
                            ch3 = -((-ch3) >> 1)
                        else:
                            ch3 = ch3 >> 1

                        out[op] = (ebp + ch3) & 0xFFFFFFFF
                        op += 1
                else:
                    # === RLE / LZ COPY (sym >= 0x14) ===
                    # Read parity value (2nd read_value)
                    v2 = self.read_value()
                    parity = (v2 & 1) - 1  # -1 or 0

                    # Read source offset components (3rd read_value)
                    # Save raw ebx from 3rd read for column calculation
                    # The 3rd read_value stores both state and raw in ebx
                    v3_raw_eax = self._read_value_raw()  # returns (sar_result, raw_eax_before_sar)

                    # Compute row offset
                    # cdq; sub eax,edx; sar eax,1 on v2
                    v2s = _s32(v2 & 0xFFFFFFFF)
                    if v2s < 0:
                        row = -((-v2s) >> 1)
                    else:
                        row = v2s >> 1
                    row += parity
                    row *= w

                    # Column offset from v3
                    v3_decoded = v3_raw_eax[0]
                    col = (v3_decoded - 2) & 0xFFFFFFFF
                    col = _s32(col)
                    col ^= parity  # xor with -1 (flip) or 0 (no-op)
                    col -= row  # subtract row offset

                    # source pixel index relative to current output position
                    src_base = op + col

                    # Read count (4th read_value)
                    v4 = self.read_value()
                    count = v4 - 1

                    if count <= 0:
                        continue

                    if sym == 0x26:  # 38: simple copy
                        for i in range(count):
                            if op >= n:
                                break
                            si = src_base + i
                            out[op] = out[si] if 0 <= si < n else 0
                            op += 1
                    else:
                        # Delta copy with per-pixel adjustment
                        rle_off = self.rle_delta[sym] if sym < len(self.rle_delta) else 0
                        for i in range(count):
                            if op >= n:
                                break
                            si = src_base + i
                            src_val = out[si] if 0 <= si < n else 0
                            # delta: out[op + rle_off] - src[si + rle_off] + src[si]
                            ref1 = op + rle_off
                            ref2 = si + rle_off
                            p1 = out[ref1] if 0 <= ref1 < n else 0
                            p2 = out[ref2] if 0 <= ref2 < n else 0
                            out[op] = ((p1 - p2 + src_val) & 0xFFFFFFFF)
                            op += 1
        except (IndexError, EOFError):
            pass

        return out

    def _read_value_raw(self):
        """Like read_value but also returns the pre-sar eax for RLE column calc.
        The 3rd RLE read needs both sar'd result and raw shifted eax."""
        a = self.state & 0xFF
        ecx = TD40[a]
        al = TB40[a]
        self.state = al
        if al == 0:
            while True:
                nb = self._rb()
                self.state = nb
                edi = nb & 0xFF
                ecx += TE40[edi]
                if TC40[edi]:
                    self.state = TC40[edi]
                    break

        a = self.state & 0xFF
        consumed = T838[a]
        eax = a + 0x100
        rem = ecx - consumed
        if rem > 0:
            eax = (eax << consumed) & 0xFFFFFF00
            nb = self._rb()
            eax = (eax + nb) & 0xFFFFFFFF
            rem -= 1
            if rem >= 8:
                nf = rem >> 3
                rem -= nf * 8
                for _ in range(nf):
                    nb = self._rb()
                    eax = ((nb + eax) << 8) & 0xFFFFFFFF
            eax = (eax * 2 + 1) & 0xFFFFFFFF
            sh = rem
        else:
            sh = ecx
        eax = (eax << (sh & 0x1F)) & 0xFFFFFFFF
        self.state = eax & 0xFF
        return (_sar(eax, 8), eax)


def decode_fd(data):
    dec = FdDecoder(data)
    pixels = dec.decode()
    return dec.width, dec.height, dec.bpp, pixels


def pixels_to_image(w, h, bpp, pixels, flip=True):
    from PIL import Image
    img = Image.new('RGB', (w, h))
    px = img.load()
    for y in range(h):
        sy = (h - 1 - y) if flip else y
        for x in range(w):
            idx = sy * w + x
            v = pixels[idx] if idx < len(pixels) else 0
            b, g, r = v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF
            px[x, y] = (r, g, b)
    return img


def detect_format(data):
    if len(data) < 4:
        return None
    b0, b1 = data[0], data[1]
    if b0 == 0x46:
        u = b1 & 0x5F
        if u == 0x44: return 'Fd'
        if u == 0x43: return 'Fc'
    if b0 == 0x38 and b1 == 0x50: return '8P'
    if b0 == 0x42 and b1 == 0x4D: return 'BM'
    return None


def convert_file(inp, outp=None):
    data = open(inp, 'rb').read()
    fmt = detect_format(data)
    if fmt != 'Fd':
        if fmt == 'BM':
            from PIL import Image
            Image.open(inp).save(outp or str(Path(inp).with_suffix('.png')))
            print(f"  {inp} -> standard BMP")
            return True
        print(f"  {inp}: {fmt or 'unknown'} format not supported yet")
        return False

    if outp is None:
        outp = str(Path(inp).with_suffix('.png'))

    print(f"  {inp} ...", end='', flush=True)
    w, h, bpp, px = decode_fd(data)
    img = pixels_to_image(w, h, bpp, px)
    img.save(outp)
    print(f" -> {outp} ({w}x{h})")
    return True


def main():
    import argparse
    ap = argparse.ArgumentParser(description='MGOS BMP Decoder (Pure Python)')
    ap.add_argument('input', help='Input .bmp file or directory')
    ap.add_argument('output', nargs='?', help='Output .png file or directory')
    ap.add_argument('--batch', action='store_true')
    args = ap.parse_args()

    if args.batch or os.path.isdir(args.input):
        outd = args.output or args.input + '_decoded'
        os.makedirs(outd, exist_ok=True)
        files = sorted(Path(args.input).glob('*.[bB][mM][pP]'))
        print(f"Found {len(files)} files")
        ok = sum(convert_file(str(f), str(Path(outd)/f.with_suffix('.png').name)) for f in files)
        print(f"Converted {ok}/{len(files)}")
    else:
        convert_file(args.input, args.output)


if __name__ == '__main__':
    main()
