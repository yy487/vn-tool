#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI5WIN 位图字库底层编解码。

处理对象：FONT00/01/02/FONTHAN 的 TBL/FNT/MSK。
- 文件层：LZSS 压缩。
- 解压后 TBL：uint16 count + count 个 uint16 code。
- FNT/MSK：按 glyph_index * width * height 索引的 1bpp-like/灰度平面。
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import subprocess
import tempfile
from typing import Iterable


# ───────────────────────────── LZSS ─────────────────────────────

def lzss_decompress(src: bytes) -> bytes:
    out = bytearray()
    window = bytearray(b'\x00' * 4096)
    wp = 0xFEE
    sp = 0
    while sp < len(src):
        flags = src[sp]
        sp += 1
        for bit in range(8):
            if sp >= len(src):
                break
            if flags & (1 << bit):
                b = src[sp]
                sp += 1
                out.append(b)
                window[wp] = b
                wp = (wp + 1) & 0xFFF
            else:
                if sp + 1 >= len(src):
                    break
                lo = src[sp]
                hi = src[sp + 1]
                sp += 2
                off = lo | ((hi & 0xF0) << 4)
                ml = (hi & 0x0F) + 3
                for k in range(ml):
                    b = window[(off + k) & 0xFFF]
                    out.append(b)
                    window[wp] = b
                    wp = (wp + 1) & 0xFFF
    return bytes(out)


def lzss_compress_literal(data: bytes) -> bytes:
    """稳定的 literal-only LZSS。体积较大，但引擎可解。"""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        chunk = data[i:i + 8]
        out.append(0xFF)
        out += chunk
        i += len(chunk)
    return bytes(out)


def lzss_compress_py(data: bytes) -> bytes:
    """较慢但能压缩的 Python LZSS，禁用 overlap 匹配，便于验证。"""
    WINDOW = 4096
    MASK = 0xFFF
    MAX_M = 18
    MIN_M = 3
    INIT = 0xFEE
    window = bytearray(b'\x00' * WINDOW)
    wp = INIT
    sp = 0
    n = len(data)
    out = bytearray()
    while sp < n:
        fp = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if sp >= n:
                break
            best_len = 0
            best_off = 0
            for back in range(1, WINDOW):
                off = (wp - back) & MASK
                ml = min(MAX_M, back)
                k = 0
                while k < ml and sp + k < n and window[(off + k) & MASK] == data[sp + k]:
                    k += 1
                if k > best_len:
                    best_len = k
                    best_off = off
                    if k == MAX_M:
                        break
            if best_len >= MIN_M:
                out.append(best_off & 0xFF)
                out.append(((best_off >> 4) & 0xF0) | ((best_len - MIN_M) & 0x0F))
                for _ in range(best_len):
                    window[wp] = data[sp]
                    wp = (wp + 1) & MASK
                    sp += 1
            else:
                flags |= (1 << bit)
                out.append(data[sp])
                window[wp] = data[sp]
                wp = (wp + 1) & MASK
                sp += 1
        out[fp] = flags
    return bytes(out)


def lzss_compress(data: bytes, c_compressor: str | None = None, *, literal: bool = False) -> bytes:
    if literal:
        comp = lzss_compress_literal(data)
        if lzss_decompress(comp) != data:
            raise RuntimeError('literal LZSS verify failed')
        return comp
    if c_compressor and os.path.exists(c_compressor):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.raw') as f:
            f.write(data)
            tmp_in = f.name
        tmp_out = tmp_in + '.lzss'
        try:
            r = subprocess.run([c_compressor, tmp_in, tmp_out], capture_output=True, timeout=300)
            if r.returncode == 0 and os.path.exists(tmp_out):
                comp = open(tmp_out, 'rb').read()
                if lzss_decompress(comp) == data:
                    return comp
        finally:
            for p in (tmp_in, tmp_out):
                if os.path.exists(p):
                    os.remove(p)
    comp = lzss_compress_py(data)
    if lzss_decompress(comp) != data:
        raise RuntimeError('python LZSS verify failed')
    return comp


# ───────────────────────────── TBL/FNT/MSK ─────────────────────────────

def parse_tbl(raw: bytes) -> list[int]:
    if len(raw) < 2:
        raise ValueError('TBL too small')
    count = int.from_bytes(raw[0:2], 'little')
    need = 2 + count * 2
    if len(raw) < need:
        raise ValueError(f'TBL truncated: count={count}, size={len(raw)}, need={need}')
    return [int.from_bytes(raw[2 + i * 2:4 + i * 2], 'little') for i in range(count)]


def build_tbl(codes: Iterable[int], *, append_zero: bool = False) -> bytes:
    codes = list(codes)
    if len(codes) > 0xFFFF:
        raise ValueError('too many glyph codes')
    out = bytearray(len(codes).to_bytes(2, 'little'))
    for code in codes:
        if not (0 <= code <= 0xFFFF):
            raise ValueError(f'bad code: {code!r}')
        out += int(code).to_bytes(2, 'little')
    if append_zero:
        out += b'\x00\x00'
    return bytes(out)


def cp932_code(ch: str) -> int:
    b = ch.encode('cp932')
    if len(b) != 2:
        raise ValueError(f'not a CP932 double-byte char: {ch!r} -> {b.hex()}')
    return b[0] | (b[1] << 8)


def code_to_cp932_char(code: int) -> str | None:
    b = bytes([code & 0xFF, (code >> 8) & 0xFF])
    try:
        return b.decode('cp932')
    except UnicodeDecodeError:
        return None


@dataclass
class FontBank:
    name: str
    glyph_w: int
    glyph_h: int
    codes: list[int]
    fnt: bytearray
    msk: bytearray
    tbl_comp_size: int = 0
    fnt_comp_size: int = 0
    msk_comp_size: int = 0

    @property
    def glyph_size(self) -> int:
        return self.glyph_w * self.glyph_h

    @property
    def slot_count(self) -> int:
        return len(self.fnt) // self.glyph_size

    def get_glyph(self, idx: int) -> tuple[bytes, bytes]:
        gs = self.glyph_size
        return bytes(self.fnt[idx * gs:(idx + 1) * gs]), bytes(self.msk[idx * gs:(idx + 1) * gs])

    def set_glyph(self, idx: int, fnt_glyph: bytes, msk_glyph: bytes) -> None:
        gs = self.glyph_size
        if len(fnt_glyph) != gs or len(msk_glyph) != gs:
            raise ValueError(f'glyph size mismatch for {self.name}')
        self.fnt[idx * gs:(idx + 1) * gs] = fnt_glyph
        self.msk[idx * gs:(idx + 1) * gs] = msk_glyph

    def append_glyph(self, code: int, fnt_glyph: bytes, msk_glyph: bytes) -> int:
        """Append one TBL entry and place its glyph at the same index.

        Important AI5WIN detail: some original banks have extra glyph slots after
        the declared TBL count, for example FONT01 count=1031 but slots=1050.
        The engine uses the TBL search result directly as glyph_index. Therefore
        if we append a code at index len(codes), its glyph MUST be written to
        slot len(codes). Appending bytes to the physical end of FNT/MSK would put
        the glyph after those spare slots and shift every newly-added glyph.
        """
        gs = self.glyph_size
        if len(fnt_glyph) != gs or len(msk_glyph) != gs:
            raise ValueError(f'glyph size mismatch for {self.name}')

        idx = len(self.codes)
        self.codes.append(code)

        # Fill an existing spare slot first, preserving TBL-index == glyph-index.
        if idx < self.slot_count:
            self.fnt[idx * gs:(idx + 1) * gs] = fnt_glyph
            self.msk[idx * gs:(idx + 1) * gs] = msk_glyph
        else:
            self.fnt += fnt_glyph
            self.msk += msk_glyph
        return idx

    def code_to_index(self) -> dict[int, int]:
        out = {}
        for i, c in enumerate(self.codes):
            if c not in out:
                out[c] = i
        return out


def bank_size(name: str) -> tuple[int, int]:
    if name.upper() == 'FONTHAN':
        return 14, 26
    return 26, 26


def load_bank(font_dir: str, name: str) -> FontBank:
    name = name.upper()
    gw, gh = bank_size(name)
    tbl_c = open(os.path.join(font_dir, name + '.TBL'), 'rb').read()
    fnt_c = open(os.path.join(font_dir, name + '.FNT'), 'rb').read()
    msk_c = open(os.path.join(font_dir, name + '.MSK'), 'rb').read()
    tbl = lzss_decompress(tbl_c)
    fnt = bytearray(lzss_decompress(fnt_c))
    msk = bytearray(lzss_decompress(msk_c))
    codes = parse_tbl(tbl)
    gs = gw * gh
    if len(fnt) % gs or len(msk) % gs:
        raise ValueError(f'{name}: FNT/MSK size is not glyph aligned')
    if len(fnt) != len(msk):
        raise ValueError(f'{name}: FNT/MSK raw size mismatch')
    if len(codes) > len(fnt) // gs:
        raise ValueError(f'{name}: TBL count > slot count')
    return FontBank(name, gw, gh, codes, fnt, msk, len(tbl_c), len(fnt_c), len(msk_c))


def save_bank(bank: FontBank, out_dir: str, *, c_compressor: str | None = None, literal: bool = False,
              append_zero_tbl: bool = False) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    tbl_raw = build_tbl(bank.codes, append_zero=append_zero_tbl)
    fnt_raw = bytes(bank.fnt)
    msk_raw = bytes(bank.msk)
    outputs = {}
    for ext, raw in [('TBL', tbl_raw), ('FNT', fnt_raw), ('MSK', msk_raw)]:
        comp = lzss_compress(raw, c_compressor, literal=literal)
        open(os.path.join(out_dir, f'{bank.name}.{ext}'), 'wb').write(comp)
        outputs[ext.lower() + '_raw_size'] = len(raw)
        outputs[ext.lower() + '_comp_size'] = len(comp)
    outputs.update({
        'count': len(bank.codes),
        'slot_count': bank.slot_count,
        'glyph_w': bank.glyph_w,
        'glyph_h': bank.glyph_h,
    })
    return outputs
