#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI5WIN CP932 借码映射生成器。

目标：
- 不再把中文直接编码成 GBK。
- 对 CP932 不可编码字符，分配一个 CP932 双字节 source_char。
- MES 注入写 source_char.encode('cp932')。
- 字库 TBL 写 source_char 的码位，FNT/MSK 画 target_char 的字形。

输入：
  charset.json: scan_chars.py 生成的规范化字符集
  subs_cn_jp.json: 可选，真实中文 -> 借用日文/繁体/稀有码位
  原版 font 目录: 用于排除/判断原 TBL 已有码位

输出：
  replace_map.json: 给 font_gen.py 和 ai5win_mes_inject.py 共用
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Iterable

from font_codec import cp932_code, load_bank
from text_normalize import normalize_text


def is_cp932_double(ch: str) -> bool:
    try:
        return len(ch.encode('cp932')) == 2
    except UnicodeEncodeError:
        return False


def is_direct_cp932_char(ch: str) -> bool:
    """能直接写入 op 0x01 的 CP932 双字节字符。换行不在这里处理。"""
    return is_cp932_double(ch)


def iter_cp932_candidate_chars() -> Iterable[str]:
    """生成兜底 CP932 双字节候选池。

    优先扫 Shift-JIS 常用双字节区，能 decode cp932 的都作为候选。
    这里不追求语义，只要求字节合法、可稳定经过原引擎的双字节文本读取逻辑。
    """
    lead_ranges = [(0x81, 0x9F), (0xE0, 0xFC)]
    trail_ranges = [(0x40, 0x7E), (0x80, 0xFC)]
    seen = set()
    for la, lb in lead_ranges:
        for lead in range(la, lb + 1):
            for ta, tb in trail_ranges:
                for trail in range(ta, tb + 1):
                    if trail == 0x7F:
                        continue
                    b = bytes([lead, trail])
                    try:
                        ch = b.decode('cp932')
                    except UnicodeDecodeError:
                        continue
                    if ch in seen:
                        continue
                    seen.add(ch)
                    # 排除控制感太强的基础符号，优先留下汉字/扩展字符。
                    if ch in {'　', '、', '。', '，', '．', '・', '「', '」', '『', '』', '（', '）'}:
                        continue
                    yield ch


def load_charset(path: str) -> list[str]:
    data = json.load(open(path, 'r', encoding='utf-8'))
    chars = data.get('chars')
    if not isinstance(chars, list):
        raise ValueError('charset.json must contain list field: chars')
    # 再 normalize 一遍，防止 charset 不是新版 scan_chars 生成的。
    out = []
    seen = set()
    for ch in chars:
        if not isinstance(ch, str):
            continue
        for c in normalize_text(ch):
            if c == '\n':
                continue
            if c not in seen:
                seen.add(c)
                out.append(c)
    return out


def load_external_map(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    raw = json.load(open(path, 'r', encoding='utf-8'))
    out = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not k:
            continue
        if isinstance(v, dict):
            v = v.get('source_char') or v.get('jp') or v.get('source')
        if not isinstance(v, str) or not v:
            continue
        nk = normalize_text(k)[0]
        nv = v[0]
        out[nk] = nv
    return out


def collect_original_codes(font_dir: str, banks: list[str]) -> dict[str, set[int]]:
    out = {}
    for b in banks:
        try:
            bank = load_bank(font_dir, b)
            out[b.upper()] = set(bank.codes)
        except FileNotFoundError:
            out[b.upper()] = set()
    return out


def build_replace_map(charset_path: str, font_dir: str, out_path: str,
                      cnjp_map_path: str | None = None,
                      banks: list[str] | None = None,
                      allow_external_overwrite: bool = True) -> dict:
    if banks is None:
        banks = ['FONT00', 'FONT01', 'FONT02']
    banks = [b.upper() for b in banks]

    chars = load_charset(charset_path)
    external = load_external_map(cnjp_map_path)
    original_codes_by_bank = collect_original_codes(font_dir, banks)
    original_codes_all = set().union(*original_codes_by_bank.values()) if original_codes_by_bank else set()

    # 已经直接 CP932 可编码的字符，不进入 replace_map；font_gen 可选择保证它们存在。
    direct_chars = []
    need_map = []
    for c in chars:
        if c == '\n':
            continue
        if is_direct_cp932_char(c):
            direct_chars.append(c)
        else:
            need_map.append(c)

    # 关键约束：source_char 不能和任何 direct_cp932 target 字符重合。
    # 否则同一个码位既要显示 source 对应的 mapped target，又要显示 direct target，
    # 在同一套 TBL/FNT/MSK 中不可能同时成立。典型现象：
    #   “无”自动借码为“校”，但译文里也有“校”，最终“无”会显示成“校”。
    direct_char_set = set(direct_chars)

    used_source = set()
    mapping = {}
    warnings = []

    # 1. 外部 cnjp_map 优先。
    for target in need_map:
        source = external.get(target)
        if not source:
            continue
        if not is_cp932_double(source):
            warnings.append(f'external map ignored: {target!r}->{source!r}, source is not CP932 double-byte')
            continue
        if source in used_source:
            warnings.append(f'external map duplicate source ignored: {target!r}->{source!r}')
            continue
        if source in direct_char_set:
            warnings.append(
                f'external map ignored: {target!r}->{source!r}, '
                f'source collides with direct CP932 char in translation'
            )
            continue
        code = cp932_code(source)
        mapping[target] = {
            'target_char': target,
            'source_char': source,
            'source_cp932_hex': source.encode('cp932').hex().upper(),
            'source_code_le': f'0x{code:04X}',
            'mode': 'external',
            # source 在原 TBL 中存在时，font_gen 必须覆盖该 index 的 glyph，否则会显示原字形。
            'overwrite_existing_glyph': bool(allow_external_overwrite and code in original_codes_all),
        }
        used_source.add(source)

    # 2. 自动补漏。自动候选默认不占用原始 TBL 已有码位，避免误改原文/系统文字。
    candidate_iter = iter_cp932_candidate_chars()
    for target in need_map:
        if target in mapping:
            continue
        while True:
            try:
                source = next(candidate_iter)
            except StopIteration as e:
                raise RuntimeError('CP932 candidate pool exhausted') from e
            if source in used_source:
                continue
            # 不能借用译文中会直接写入的 CP932 字符，否则字库码位冲突。
            if source in direct_char_set:
                continue
            code = cp932_code(source)
            if code in original_codes_all:
                continue
            break
        mapping[target] = {
            'target_char': target,
            'source_char': source,
            'source_cp932_hex': source.encode('cp932').hex().upper(),
            'source_code_le': f'0x{code:04X}',
            'mode': 'auto',
            'overwrite_existing_glyph': False,
        }
        used_source.add(source)

    result = {
        'version': 1,
        'encoding': 'cp932-borrow',
        'normalize': {
            'ascii_to_fullwidth': True,
            'space_to_ideographic': True,
        },
        'banks': banks,
        'stats': {
            'charset_total': len(chars),
            'direct_cp932': len(direct_chars),
            'mapped_total': len(mapping),
            'external_used': sum(1 for v in mapping.values() if v['mode'] == 'external'),
            'auto_used': sum(1 for v in mapping.values() if v['mode'] == 'auto'),
            'overwrite_existing_glyph': sum(1 for v in mapping.values() if v.get('overwrite_existing_glyph')),
            'source_direct_collisions': sum(1 for v in mapping.values() if v.get('source_char') in direct_char_set),
        },
        'direct_cp932_chars': direct_chars,
        'chars': mapping,
        'warnings': warnings,
    }
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    json.dump(result, open(out_path, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    return result


class ReplaceMapper:
    def __init__(self, map_data: dict):
        self.data = map_data
        self.map = {k: v['source_char'] for k, v in map_data.get('chars', {}).items()}

    @classmethod
    def load(cls, path: str) -> 'ReplaceMapper':
        return cls(json.load(open(path, 'r', encoding='utf-8')))

    def normalize(self, s: str) -> str:
        return normalize_text(s)

    def replace(self, s: str) -> str:
        s = normalize_text(s)
        return ''.join(self.map.get(c, c) for c in s)

    def encode_cp932(self, s: str, *, require_double: bool = True) -> bytes:
        mapped = self.replace(s)
        out = bytearray()
        for src, orig in zip(mapped, normalize_text(s)):
            if src == '\n':
                # TEXT 指令中一般不应出现原始换行；保守保留 0x0A。
                out.append(0x0A)
                continue
            try:
                b = src.encode('cp932')
            except UnicodeEncodeError as e:
                raise UnicodeEncodeError('cp932-borrow', orig, 0, 1, f'no mapping for char {orig!r}') from e
            if require_double and len(b) != 2:
                raise ValueError(f'encoded char is not double-byte: original={orig!r}, source={src!r}, bytes={b.hex()}')
            out += b
        return bytes(out)


def main():
    ap = argparse.ArgumentParser(description='Build AI5WIN CP932 borrow replace_map.json')
    ap.add_argument('charset_json')
    ap.add_argument('font_dir', help='directory containing original FONT00/01/02 files')
    ap.add_argument('out_json')
    ap.add_argument('--cnjp-map', default=None, help='optional subs_cn_jp.json')
    ap.add_argument('--banks', default='FONT00,FONT01,FONT02')
    ap.add_argument('--no-external-overwrite', action='store_true')
    args = ap.parse_args()
    banks = [x.strip().upper() for x in args.banks.split(',') if x.strip()]
    data = build_replace_map(
        args.charset_json,
        args.font_dir,
        args.out_json,
        cnjp_map_path=args.cnjp_map,
        banks=banks,
        allow_external_overwrite=not args.no_external_overwrite,
    )
    st = data['stats']
    print(f"replace_map: {args.out_json}")
    print(f"  charset={st['charset_total']} direct_cp932={st['direct_cp932']} mapped={st['mapped_total']}")
    print(f"  external={st['external_used']} auto={st['auto_used']} overwrite_existing={st['overwrite_existing_glyph']}")
    if data.get('warnings'):
        print(f"  warnings={len(data['warnings'])}")


if __name__ == '__main__':
    main()
