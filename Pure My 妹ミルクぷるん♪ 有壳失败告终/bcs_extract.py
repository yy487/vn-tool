#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bcs_extract.py - Tanuki Soft / Kaeru Soft / Rune .bcs 文本提取器

支持引擎容器:
  - BCS\\0 + GMS\\0  (老引擎, 双层 LZSS, 内层 invert)
  - TSV\\0 + TNK\\0  (新引擎, Blowfish key="TLibDefKey", 需 pycryptodome)

提取策略:
  - 仅提取 %text% 列非空且非 ■ 章节注释开头的行
  - %name% 列作为说话人 (空 -> name="")
  - 每条 entry 记录注入需要的位置信息: row 索引 + name/text 在 index_tbl
    中的 entry 字节偏移 + 原 offset/原文字节
  - 选项分支 ($jump_item 等命令列内容) 不提取

JSON 格式 (GalTransl 兼容):
  [
    {"name": "礼矢", "message": "「はぁ～あ……寒いっ！」",
     "_meta": {"row":14, "name_entry_off":..., "text_entry_off":..., ...}},
    ...
  ]

用法:
    python bcs_extract.py <input.bcs|dir> [-o outdir]
"""
import os
import sys
import json
import struct
import argparse

from bcs_lzss import lzss_unpack


# ============================================================
# Blowfish (仅 TSV 路径)
# ============================================================
def blowfish_decrypt(data: bytes, key: bytes) -> bytes:
    try:
        from Crypto.Cipher import Blowfish as BF
    except ImportError:
        raise RuntimeError(
            "TSV 类型 .bcs 需要 pycryptodome:\n"
            "  pip install pycryptodome --break-system-packages"
        )
    cipher = BF.new(key, BF.MODE_ECB)
    n = len(data) & ~7
    out = bytearray(data)
    if n:
        out[:n] = cipher.decrypt(bytes(out[:n]))
    return bytes(out)


# ============================================================
# 解析 .bcs
# ============================================================
def parse_bcs(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("文件过小")

    magic = data[:4]
    if magic[:3] == b'TSV':
        is_tsv = True
    elif magic[:3] == b'BCS':
        is_tsv = False
    else:
        raise ValueError(f"非 BCS/TSV 文件 (magic={magic!r})")

    unp_size, obj_cnt, obj_mark, obj_parts, body_size = struct.unpack('<5I', data[4:24])

    unpacked = lzss_unpack(data, 24, unp_size)
    if len(unpacked) != unp_size:
        print(f"  [warn] 一层 LZSS 输出 {len(unpacked)} != {unp_size}", file=sys.stderr)

    first_tbl_size = obj_cnt * 8
    second_tbl_size = obj_parts * 8
    first_tbl = unpacked[:first_tbl_size]
    index_tbl = unpacked[first_tbl_size:first_tbl_size + second_tbl_size]
    third = unpacked[first_tbl_size + second_tbl_size:]

    num_cols = struct.unpack_from('<I', first_tbl, 0)[0]

    if is_tsv:
        if third[:3] != b'TNK':
            print(f"  [warn] 期望 TNK 段, 实际 {third[:4]!r}", file=sys.stderr)
        strpool = blowfish_decrypt(third[12:], b"TLibDefKey")
    else:
        if third[:3] != b'GMS':
            print(f"  [warn] 期望 GMS 段, 实际 {third[:4]!r}", file=sys.stderr)
        strpool = lzss_unpack(third, 16, body_size, invert=True)

    total_entries = len(index_tbl) // 8
    if total_entries % num_cols != 0:
        print(f"  [warn] entries {total_entries} 不能被 numCols {num_cols} 整除",
              file=sys.stderr)
    num_rows = total_entries // num_cols

    return {
        'magic': magic[:3].decode(),
        'is_tsv': is_tsv,
        'num_cols': num_cols,
        'num_rows': num_rows,
        'index_tbl': index_tbl,
        'strpool': strpool,
    }


# ============================================================
# 列名识别
# ============================================================
def get_column_names(parsed):
    """从 row 0 解出 ['%line%', '%seq%', ..., '%text%']"""
    index_tbl = parsed['index_tbl']
    strpool = parsed['strpool']
    num_cols = parsed['num_cols']
    cols = []
    for c in range(num_cols):
        ent = c * 8
        op = struct.unpack_from('<I', index_tbl, ent)[0] & 0b11
        val = struct.unpack_from('<I', index_tbl, ent + 4)[0]
        if op == 0x03:
            end = strpool.find(b'\x00', val)
            if end < 0:
                end = len(strpool)
            cols.append(strpool[val:end].decode('cp932', errors='replace'))
        else:
            cols.append('')
    return cols


def find_col(cols, name):
    """找 %xxx% 列, 容忍 %xxx 缺尾%"""
    if name in cols:
        return cols.index(name)
    short = name.rstrip('%')
    for i, c in enumerate(cols):
        if c.startswith(short):
            return i
    return -1


# ============================================================
# 读 entry
# ============================================================
def read_entry(index_tbl, strpool, row, col, num_cols):
    """返回 (op, value, decoded_str_or_None, original_byte_count, entry_byte_offset)"""
    ent_off = (row * num_cols + col) * 8
    op = struct.unpack_from('<I', index_tbl, ent_off)[0] & 0b11
    val = struct.unpack_from('<I', index_tbl, ent_off + 4)[0]
    if op == 0x03:
        end = strpool.find(b'\x00', val)
        if end < 0:
            end = len(strpool)
        raw = strpool[val:end]
        try:
            s = raw.decode('cp932')
        except UnicodeDecodeError:
            s = raw.decode('cp932', errors='replace')
        return (op, val, s, len(raw), ent_off)
    else:
        return (op, val, None, 0, ent_off)


# ============================================================
# 提取
# ============================================================
def extract_to_json(parsed):
    index_tbl = parsed['index_tbl']
    strpool = parsed['strpool']
    num_cols = parsed['num_cols']
    num_rows = parsed['num_rows']

    cols = get_column_names(parsed)
    text_col = find_col(cols, '%text%')
    if text_col < 0:
        raise ValueError(f"找不到 %text% 列, 列名: {cols}")
    name_col = find_col(cols, '%name%')
    if name_col < 0:
        print(f"  [warn] 找不到 %name% 列, 全部按旁白处理", file=sys.stderr)

    out = []
    skipped_chapter = 0
    skipped_empty = 0

    for r in range(1, num_rows):  # row 0 是表头
        text_op, text_val, text_str, text_orig, text_ent = read_entry(
            index_tbl, strpool, r, text_col, num_cols)

        if text_op != 0x03 or text_str is None:
            continue
        if not text_str.strip():
            skipped_empty += 1
            continue
        if text_str.lstrip().startswith('■'):
            skipped_chapter += 1
            continue

        name_str = ""
        name_meta = {
            'name_entry_off': None,
            'name_str_off': None,
            'name_orig_bytes': 0,
        }
        if name_col >= 0:
            n_op, n_val, n_str, n_orig, n_ent = read_entry(
                index_tbl, strpool, r, name_col, num_cols)
            if n_op == 0x03 and n_str is not None and n_str.strip():
                name_str = n_str
                name_meta = {
                    'name_entry_off': n_ent,
                    'name_str_off': n_val,
                    'name_orig_bytes': n_orig,
                }

        out.append({
            'name': name_str,
            'message': text_str,
            '_meta': {
                'row': r,
                **name_meta,
                'text_entry_off': text_ent,
                'text_str_off': text_val,
                'text_orig_bytes': text_orig,
            }
        })

    stats = {
        'extracted': len(out),
        'skipped_chapter_marker': skipped_chapter,
        'skipped_empty': skipped_empty,
        'total_rows': num_rows - 1,
    }
    return out, stats


# ============================================================
# 主入口
# ============================================================
def process_one(in_path, out_dir, overwrite, verbose):
    base = os.path.splitext(os.path.basename(in_path))[0]
    if base.lower() in ('_emote', 'emote'):
        if verbose:
            print(f"[skip] {in_path}: emote 文件不提取")
        return

    out_path = os.path.join(out_dir, base + '.json')
    if not overwrite and os.path.exists(out_path):
        print(f"[skip] {out_path} 已存在 (--overwrite 强制覆盖)")
        return

    try:
        parsed = parse_bcs(in_path)
        items, stats = extract_to_json(parsed)
    except Exception as e:
        print(f"[FAIL] {in_path}: {e}")
        return

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False, indent=2)

    if verbose:
        print(f"[OK]   {in_path}")
        print(f"       magic={parsed['magic']}  cols={parsed['num_cols']}  "
              f"rows={parsed['num_rows']}  strpool={len(parsed['strpool'])}B")
        print(f"       extracted={stats['extracted']}  "
              f"skipped_chapter={stats['skipped_chapter_marker']}  "
              f"skipped_empty={stats['skipped_empty']}")
    else:
        print(f"[OK]   {in_path} -> {out_path}  ({stats['extracted']} 条)")


def main():
    ap = argparse.ArgumentParser(
        description="Tanuki/Kaeru/Rune .bcs 文本提取器 (GalTransl JSON)")
    ap.add_argument('input', help="单个 .bcs 文件或目录")
    ap.add_argument('-o', '--output', default='.', help="输出目录 (默认当前)")
    ap.add_argument('--overwrite', action='store_true', help="覆盖已存在")
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)

    if os.path.isdir(args.input):
        files = sorted(
            os.path.join(args.input, fn)
            for fn in os.listdir(args.input)
            if fn.lower().endswith('.bcs')
        )
        if not files:
            print(f"目录 {args.input} 下无 .bcs 文件")
            return
        ok = fail = 0
        for fp in files:
            try:
                process_one(fp, args.output, args.overwrite, args.verbose)
                ok += 1
            except Exception as e:
                print(f"[FAIL] {fp}: {e}")
                fail += 1
        print(f"\n完成: {ok} 成功, {fail} 失败, 共 {len(files)} 个文件")
    else:
        process_one(args.input, args.output, args.overwrite, args.verbose)


if __name__ == '__main__':
    main()
