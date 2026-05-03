#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI5WIN 多 bank 位图字库生成器（CP932 借码位版）。

输入 replace_map.json，而不是 charset.json。
同一个 replace_map 同时给本工具和 ai5win_mes_inject.py 使用，保证：
  MES 写入的 CP932 source_char == TBL 中查找的 source_char
  FNT/MSK 对应 glyph == target_char 的中文字形

用法：
  python font_gen.py <replace_map.json> <font.ttf> <orig_font_dir> <out_dir> [选项]

例：
  python font_gen.py build/replace_map.json msyh.ttc data_out build/font_out --banks FONT00,FONT01,FONT02
"""
from __future__ import annotations

import argparse
import json
import os
import shutil

from PIL import Image, ImageDraw, ImageFont

from font_codec import cp932_code, load_bank, save_bank


def find_c_compressor() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ('lzss_comp.exe', 'lzss_comp'):
        p = os.path.join(here, name)
        if os.path.exists(p):
            return p
    return None


def render_glyph(ch: str, font, glyph_w: int, glyph_h: int, *, mask_mode: str = 'clear') -> tuple[bytes, bytes]:
    img = Image.new('L', (glyph_w, glyph_h), 0)
    draw = ImageDraw.Draw(img)

    # 以常用汉字确定统一基线，外部会传入同一个 font；这里每字水平居中。
    bbox = font.getbbox(ch)
    if not bbox:
        return bytes(glyph_w * glyph_h), bytes(glyph_w * glyph_h)
    cw = bbox[2] - bbox[0]
    ch_h = bbox[3] - bbox[1]
    x = (glyph_w - cw) // 2 - bbox[0]
    y = (glyph_h - ch_h) // 2 - bbox[1]
    draw.text((x, y), ch, fill=255, font=font)
    raw = img.tobytes()

    if mask_mode == 'smooth':
        msk = bytes(min(p >> 4, 0x0F) if p else 0 for p in raw)
    else:
        # 引擎里 MSK & 0x10 是“直接绘制 FNT 灰度”的硬绘制分支。
        msk = bytes(0x10 if p else 0x00 for p in raw)
    return bytes(raw), msk


def is_cjk_char(ch: str) -> bool:
    if not ch:
        return False
    o = ord(ch[0])
    return (0x3400 <= o <= 0x4DBF) or (0x4E00 <= o <= 0x9FFF) or (0xF900 <= o <= 0xFAFF)


def bank_preview(bank, out_path: str, max_glyphs: int = 500) -> None:
    gw, gh = bank.glyph_w, bank.glyph_h
    gs = gw * gh
    n = min(max_glyphs, bank.slot_count)
    cols = 50
    rows = (n + cols - 1) // cols
    margin = 2
    img = Image.new('RGBA', (cols * (gw + margin), rows * (gh + margin)), (30, 30, 30, 255))
    for i in range(n):
        gx = (i % cols) * (gw + margin)
        gy = (i // cols) * (gh + margin)
        off = i * gs
        for y in range(gh):
            base = off + y * gw
            for x in range(gw):
                v = bank.fnt[base + x]
                if v:
                    img.putpixel((gx + x, gy + y), (255, 255, 255, v))
    img.save(out_path)


def load_replace_map(path: str) -> dict:
    data = json.load(open(path, 'r', encoding='utf-8'))
    if data.get('encoding') != 'cp932-borrow':
        raise ValueError('replace_map.json encoding must be cp932-borrow')
    return data


def build_font_banks(map_path: str, font_path: str, orig_dir: str, out_dir: str,
                     banks: list[str], font_size: int, mask_mode: str,
                     literal_lzss: bool = False, copy_fonthan: bool = True) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    data = load_replace_map(map_path)
    entries = list(data.get('chars', {}).values())
    # direct_cp932_chars 也必须参与字库保证。
    # 之前版本只处理 mapped chars，导致“叮/当/小/心”等能直接 CP932 编码但
    # 不在某个 bank TBL 里的字符被注入后查不到，表现为缺字、源字或错字。
    direct_chars = list(dict.fromkeys(data.get('direct_cp932_chars', [])))

    # 同一个 CP932 码位不能同时承担 mapped source 和 direct target。
    # 一旦 replace_map 里出现 source_char ∈ direct_cp932_chars，font_gen 无法正确生成字库：
    # 先覆盖 mapped glyph 会导致 direct 字显示成 mapped target；
    # 后覆盖 direct glyph 又会导致 mapped 字显示成 source/direct 字。
    source_to_target = {ent['source_char']: ent['target_char'] for ent in entries}
    collisions = [(src, source_to_target[src]) for src in direct_chars if src in source_to_target]
    if collisions:
        examples = ', '.join(f'{target}->借用{src}' for src, target in collisions[:20])
        raise ValueError(
            'replace_map has source/direct collisions. Rebuild replace_map with v6 hanzi_replacer.py. '
            f'Examples: {examples}'
        )

    font = ImageFont.truetype(font_path, font_size)
    rendered_cache: dict[tuple[str, int, int], tuple[bytes, bytes]] = {}

    c_comp = find_c_compressor()
    manifest = {
        'version': 1,
        'encoding': 'cp932-borrow',
        'map': os.path.abspath(map_path),
        'font': os.path.abspath(font_path),
        'font_size': font_size,
        'mask_mode': mask_mode,
        'banks': {},
        'notes': [
            'If a bank raw size is larger than original allocation, EXE size constants may need patching.',
            'FONTHAN is normally kept original; ASCII should be normalized to fullwidth before injection.',
        ],
    }

    for bank_name in banks:
        bank_name = bank_name.upper()
        print(f'[{bank_name}] load original')
        bank = load_bank(orig_dir, bank_name)
        old = {
            'count': len(bank.codes),
            'slot_count': bank.slot_count,
            'tbl_comp_size': bank.tbl_comp_size,
            'fnt_comp_size': bank.fnt_comp_size,
            'msk_comp_size': bank.msk_comp_size,
            'tbl_raw_size': 2 + len(bank.codes) * 2,
            'fnt_raw_size': len(bank.fnt),
            'msk_raw_size': len(bank.msk),
        }
        idx_by_code = bank.code_to_index()
        overwritten = 0
        appended = 0
        direct_kept = 0
        direct_overwritten = 0
        direct_appended = 0
        skipped_direct_single = 0

        # A. 先处理 mapped chars：source_char 码位显示 target_char glyph。
        #    如果 source_code 已在原 TBL，必须覆盖第一个命中 index；否则引擎线性查表
        #    会先命中旧 glyph，追加同码位没有意义。
        for ent in entries:
            target = ent['target_char']
            source = ent['source_char']
            code = cp932_code(source)
            key = (target, bank.glyph_w, bank.glyph_h)
            if key not in rendered_cache:
                rendered_cache[key] = render_glyph(target, font, bank.glyph_w, bank.glyph_h, mask_mode=mask_mode)
            fnt_g, msk_g = rendered_cache[key]

            if code in idx_by_code:
                # v5: mapped source_char 一旦参与注入，就必须让该码位显示 target_char。
                # 不再依赖 replace_map 里的 overwrite_existing_glyph 标记；否则会出现繁体/借码源字直接显示。
                bank.set_glyph(idx_by_code[code], fnt_g, msk_g)
                overwritten += 1
            else:
                idx_by_code[code] = bank.append_glyph(code, fnt_g, msk_g)
                appended += 1

        # B. 再保证 direct CP932 字符在每个双字节 bank 里都能查到。
        #    注入器会把这些字符直接 encode('cp932')，如果 bank 的 TBL 没有该码位，
        #    游戏会查表失败。已有的保留原 glyph，缺失的用当前 TTF 补画。
        if bank_name != 'FONTHAN':
            for ch in direct_chars:
                if ch == '\n':
                    continue
                try:
                    code = cp932_code(ch)
                except Exception:
                    skipped_direct_single += 1
                    continue
                key = (ch, bank.glyph_w, bank.glyph_h)
                if key not in rendered_cache:
                    rendered_cache[key] = render_glyph(ch, font, bank.glyph_w, bank.glyph_h, mask_mode=mask_mode)
                fnt_g, msk_g = rendered_cache[key]

                if code in idx_by_code:
                    # v5: direct CP932 的汉字也必须重绘。
                    # 原 bank 中已有同码位时，保留旧 glyph 会导致“叮”显示成原字库里的其他字形。
                    # 标点/假名等非 CJK 保留原样，避免破坏原 UI 符号风格。
                    if is_cjk_char(ch):
                        bank.set_glyph(idx_by_code[code], fnt_g, msk_g)
                        direct_overwritten += 1
                    else:
                        direct_kept += 1
                    continue
                idx_by_code[code] = bank.append_glyph(code, fnt_g, msk_g)
                direct_appended += 1

        print(f'[{bank_name}] mapped_overwritten={overwritten}, mapped_appended={appended}, '
              f'direct_overwritten={direct_overwritten}, direct_kept={direct_kept}, '
              f'direct_appended={direct_appended}, count={len(bank.codes)}, slots={bank.slot_count}')
        info = save_bank(bank, out_dir, c_compressor=c_comp, literal=literal_lzss)
        info['old'] = old
        info['overwritten'] = overwritten
        info['appended'] = appended
        info['direct_kept'] = direct_kept
        info['direct_overwritten'] = direct_overwritten
        info['direct_appended'] = direct_appended
        info['skipped_direct_single'] = skipped_direct_single
        info['expanded'] = info['fnt_raw_size'] > old['fnt_raw_size'] or info['msk_raw_size'] > old['msk_raw_size']
        manifest['banks'][bank_name] = info
        try:
            bank_preview(bank, os.path.join(out_dir, f'{bank_name}_preview.png'))
        except Exception as e:
            print(f'[{bank_name}] preview failed: {e}')

    if copy_fonthan:
        for ext in ('TBL', 'FNT', 'MSK'):
            src = os.path.join(orig_dir, f'FONTHAN.{ext}')
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(out_dir, f'FONTHAN.{ext}'))
        manifest['banks']['FONTHAN'] = {'copied_original': True}

    json.dump(manifest, open(os.path.join(out_dir, 'build_manifest.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    shutil.copy2(map_path, os.path.join(out_dir, 'replace_map.json'))
    print(f'完成: {out_dir}')
    print('  build_manifest.json')
    return manifest


def main():
    ap = argparse.ArgumentParser(description='Build AI5WIN bitmap font banks from replace_map.json')
    ap.add_argument('replace_map')
    ap.add_argument('font_ttf')
    ap.add_argument('orig_font_dir')
    ap.add_argument('out_dir')
    ap.add_argument('--banks', default='FONT00,FONT01,FONT02')
    ap.add_argument('--size', type=int, default=22)
    ap.add_argument('--mask-mode', choices=['clear', 'smooth'], default='clear')
    ap.add_argument('--literal-lzss', action='store_true', help='use larger literal-only LZSS')
    ap.add_argument('--no-copy-fonthan', action='store_true')
    args = ap.parse_args()
    banks = [x.strip().upper() for x in args.banks.split(',') if x.strip()]
    build_font_banks(
        args.replace_map, args.font_ttf, args.orig_font_dir, args.out_dir,
        banks, args.size, args.mask_mode,
        literal_lzss=args.literal_lzss,
        copy_fonthan=not args.no_copy_fonthan,
    )


if __name__ == '__main__':
    main()
