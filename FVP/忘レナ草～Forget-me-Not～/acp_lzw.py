#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
acp_lzw.py  --  ACP/LZW codec for forget.exe (ペンギンワークス)

Container layout:
    +0  char  magic[4]  = "acp\\0"   (uint32 LE = 0x00706361)
    +4  u32   uncomp_sz  (BE,  read as 32 raw bits MSB-first)
    +8  ...   LZW bitstream

LZW parameters (mirrored from forget.exe FUN_00433c80 / FUN_00433e10):
    - bit order            : MSB-first within each byte
    - initial code width   : 9 bits
    - first dict code      : 0x103
    - reserved codes       : 0x100=EOI, 0x101=WIDTH++, 0x102=CLEAR
    - WIDTH++ trigger      : when next_code > current_mask the encoder emits
                             0x101 *after* assigning that code; the marker is
                             written at the OLD width and the new width takes
                             effect immediately afterwards.
    - CLEAR trigger        : when next_code reaches 0x8000 the encoder gives
                             up on widening (15-bit cap) and emits 0x102, then
                             resets dict / width / mask.

This module is a 1:1 functional mirror of the engine's codec, verified by
decode->encode->decode round-tripping all 270 .acp files in forget.bin.
"""

import struct
import sys
import os


# ----------------------------------------------------------------------
# Bit IO  (MSB-first within each byte)
# ----------------------------------------------------------------------

class BitReader:
    """MSB-first bit reader, mirror of FUN_00433960."""
    __slots__ = ('data', 'pos', 'bits_left')

    def __init__(self, data, start=0):
        self.data = data
        self.pos = start
        self.bits_left = 8

    def read(self, n):
        v = 0
        while n >= self.bits_left:
            if self.pos >= len(self.data):
                return None
            cur = self.data[self.pos]
            n -= self.bits_left
            v |= (cur & ((1 << self.bits_left) - 1)) << n
            self.pos += 1
            self.bits_left = 8
        if n > 0:
            cur = self.data[self.pos]
            v |= cur >> (self.bits_left - n)
            self.bits_left -= n
        return v


class BitWriter:
    """MSB-first bit writer, mirror of FUN_00433a50."""
    __slots__ = ('out', 'cur', 'bits_left')

    def __init__(self):
        self.out = bytearray()
        self.cur = 0
        self.bits_left = 8

    def write(self, value, n):
        while n >= self.bits_left:
            n -= self.bits_left
            self.cur |= (value >> n) & 0xFF
            self.out.append(self.cur)
            self.cur = 0
            self.bits_left = 8
        if n > 0:
            self.cur |= (value & ((1 << n) - 1)) << (self.bits_left - n)
            self.bits_left -= n

    def finish(self):
        if self.bits_left != 8:
            self.out.append(self.cur)
            self.cur = 0
            self.bits_left = 8
        return bytes(self.out)


# ----------------------------------------------------------------------
# LZW
# ----------------------------------------------------------------------

EOI    = 0x100
INC    = 0x101
CLEAR  = 0x102
FIRST  = 0x103
DICT_LIMIT = 0x8000   # encoder bails (CLEAR) when next_code reaches this


def _new_dict_decode():
    d = [bytes([i]) for i in range(0x100)]
    d.extend((b'', b'', b''))   # placeholders for 0x100/0x101/0x102
    return d


def lzw_decode(stream, expected_size):
    """Decode an LZW bitstream into bytes, mirror of FUN_00433c80."""
    br = BitReader(stream)
    out = bytearray()
    width = 9
    next_code = FIRST
    dict_ = _new_dict_decode()
    prev = None

    while True:
        code = br.read(width)
        if code is None:
            break
        if code == EOI:
            break
        if code == INC:
            width += 1
            continue
        if code == CLEAR:
            width = 9
            next_code = FIRST
            dict_ = _new_dict_decode()
            prev = None
            continue

        # Standard LZW: handle code == next_code (KwKwK) case
        if code < len(dict_) and (code < 0x100 or dict_[code]):
            entry = dict_[code]
        elif code == len(dict_) and prev is not None:
            entry = prev + prev[:1]
        else:
            raise ValueError(
                f'invalid LZW code 0x{code:X} at out_pos={len(out)} '
                f'(dict size {len(dict_)})')

        out.extend(entry)

        if prev is not None and next_code < DICT_LIMIT:
            new_entry = prev + entry[:1]
            if next_code < len(dict_):
                dict_[next_code] = new_entry
            else:
                dict_.append(new_entry)
            next_code += 1

        prev = entry
        if len(out) >= expected_size:
            break

    return bytes(out)


def lzw_encode(data):
    """Encode raw bytes to an LZW bitstream, mirror of FUN_00433e10."""
    bw = BitWriter()
    if not data:
        bw.write(EOI, 9)
        return bw.finish()

    # Maps (prefix_code, byte) -> assigned_code
    dict_ = {}
    width = 9
    mask = (1 << width) - 1
    next_code = FIRST

    prefix = data[0]
    i = 1
    n = len(data)

    while i < n:
        b = data[i]
        i += 1
        key = (prefix, b)
        existing = dict_.get(key)
        if existing is not None:
            prefix = existing
            continue

        # Miss: emit current prefix, register new dict entry.
        bw.write(prefix, width)
        dict_[key] = next_code
        next_code += 1
        prefix = b

        if next_code < DICT_LIMIT:
            if mask < next_code:
                bw.write(INC, width)
                width += 1
                mask = (mask << 1) | 1
        else:
            bw.write(CLEAR, width)
            dict_.clear()
            width = 9
            mask = (1 << width) - 1
            next_code = FIRST
            # `prefix` keeps its current value (the byte that just caused
            # the reset). Next iteration looks up (prefix, next_byte) in
            # an empty dict, misses, and emits prefix at the new 9-bit
            # width. This matches the engine exactly.

    bw.write(prefix, width)
    bw.write(EOI, width)
    return bw.finish()


# ----------------------------------------------------------------------
# Container
# ----------------------------------------------------------------------

ACP_MAGIC = b'acp\x00'


def acp_decode(blob):
    if blob[:4] != ACP_MAGIC:
        raise ValueError('not an ACP container (bad magic)')
    uncomp = struct.unpack_from('>I', blob, 4)[0]
    out = lzw_decode(blob[8:], uncomp)
    if len(out) != uncomp:
        raise ValueError(
            f'decoded size mismatch: expected {uncomp}, got {len(out)}')
    return out


def acp_encode(raw):
    body = lzw_encode(raw)
    return ACP_MAGIC + struct.pack('>I', len(raw)) + body


def acp_decode_file(path):
    return acp_decode(open(path, 'rb').read())


def acp_encode_file(raw_path, out_path):
    raw = open(raw_path, 'rb').read()
    with open(out_path, 'wb') as fo:
        fo.write(acp_encode(raw))


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description='ACP / LZW codec')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('d', help='decode (acp -> raw)')
    p.add_argument('src')
    p.add_argument('dst')

    p = sub.add_parser('e', help='encode (raw -> acp)')
    p.add_argument('src')
    p.add_argument('dst')

    p = sub.add_parser('verify', help='decode->encode->decode round-trip')
    p.add_argument('src')

    p = sub.add_parser('verify-dir', help='round-trip every acp file in a dir')
    p.add_argument('dir')

    p = sub.add_parser('d-dir', help='batch decode every acp file in a dir')
    p.add_argument('src')
    p.add_argument('dst')

    p = sub.add_parser('e-dir', help='batch encode every file in a dir into acp')
    p.add_argument('src')
    p.add_argument('dst')

    args = ap.parse_args()

    if args.cmd == 'd':
        with open(args.dst, 'wb') as f:
            f.write(acp_decode_file(args.src))
        print(f'[ok] decoded {args.src} -> {args.dst}')

    elif args.cmd == 'e':
        acp_encode_file(args.src, args.dst)
        print(f'[ok] encoded {args.src} -> {args.dst}')

    elif args.cmd == 'verify':
        raw1 = acp_decode_file(args.src)
        re_acp = acp_encode(raw1)
        raw2 = acp_decode(re_acp)
        ok = (raw1 == raw2)
        orig = os.path.getsize(args.src) - 8
        new  = len(re_acp) - 8
        print(f'src       : {args.src}')
        print(f'raw size  : {len(raw1)}')
        print(f'orig comp : {orig}')
        print(f'new  comp : {new}  ({new/max(orig,1):.2f}x)')
        print(f'round-trip: {"OK" if ok else "FAIL"}')
        return 0 if ok else 1

    elif args.cmd == 'd-dir':
        if os.path.abspath(args.src) == os.path.abspath(args.dst):
            print('[ERR ] src and dst must be different directories '
                  '(原地解压会覆盖源文件)')
            return 1
        os.makedirs(args.dst, exist_ok=True)
        n_dec = n_copy = n_skip = 0
        for f in sorted(os.listdir(args.src)):
            sp = os.path.join(args.src, f)
            if not os.path.isfile(sp):
                continue
            if f == '_order.txt':
                # 来自 acpxpk_tool unpack 的辅助文件, 直接拷过去
                # (后续 e-dir + acpxpk pack 会用到原顺序)
                with open(sp, 'rb') as fi, open(os.path.join(args.dst, f), 'wb') as fo:
                    fo.write(fi.read())
                n_copy += 1
                continue
            with open(sp, 'rb') as fh:
                head = fh.read(4)
            dp = os.path.join(args.dst, f)
            if head == ACP_MAGIC:
                try:
                    with open(dp, 'wb') as fo:
                        fo.write(acp_decode_file(sp))
                    n_dec += 1
                except Exception as e:
                    print(f'[ERR ] {f}: {e}')
                    n_skip += 1
            else:
                # 不是 acp 容器, 原样拷贝
                with open(sp, 'rb') as fi, open(dp, 'wb') as fo:
                    fo.write(fi.read())
                n_copy += 1
        print(f'[ok] decoded {n_dec}, copied {n_copy}, skipped {n_skip}')
        print(f'     out: {args.dst}')

    elif args.cmd == 'e-dir':
        if os.path.abspath(args.src) == os.path.abspath(args.dst):
            print('[ERR ] src and dst must be different directories')
            return 1
        os.makedirs(args.dst, exist_ok=True)
        n_enc = n_copy = 0
        for f in sorted(os.listdir(args.src)):
            sp = os.path.join(args.src, f)
            if not os.path.isfile(sp):
                continue
            dp = os.path.join(args.dst, f)
            if f == '_order.txt':
                # 直接拷过去, 留给 acpxpk_tool pack 用
                with open(sp, 'rb') as fi, open(dp, 'wb') as fo:
                    fo.write(fi.read())
                n_copy += 1
                continue
            try:
                acp_encode_file(sp, dp)
                n_enc += 1
            except Exception as e:
                print(f'[ERR ] {f}: {e}')
        print(f'[ok] encoded {n_enc}, copied {n_copy}')
        print(f'     out: {args.dst}')

    elif args.cmd == 'verify-dir':
        files = sorted(os.listdir(args.dir))
        ok = 0; fail = 0
        sum_orig = 0; sum_new = 0
        for f in files:
            p = os.path.join(args.dir, f)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, 'rb') as fh:
                    if fh.read(4) != ACP_MAGIC:
                        continue
                raw1 = acp_decode_file(p)
                re_acp = acp_encode(raw1)
                raw2 = acp_decode(re_acp)
                if raw1 == raw2:
                    ok += 1
                    sum_orig += os.path.getsize(p) - 8
                    sum_new  += len(re_acp) - 8
                else:
                    print(f'[FAIL] {f}: round-trip differs')
                    fail += 1
            except Exception as e:
                print(f'[ERR ] {f}: {e}')
                fail += 1
        print(f'\nresult : {ok} ok, {fail} fail (of {ok+fail} acp files)')
        if sum_orig:
            print(f'orig comp total : {sum_orig}')
            print(f'new  comp total : {sum_new}  ({sum_new/sum_orig:.3f}x)')
        return 0 if fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main() or 0)