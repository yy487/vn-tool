#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bcs_inject.py - Tanuki Soft / Kaeru Soft / Rune .bcs 文本注入器

A 方案 (零风险):
  - 字符串池零共享 (实测验证), 每条 op=0x03 entry 独占自己的 offset
  - 译文 ≤ 原文字节: 原位覆盖 + NUL 填充 (offset 不变, 字符串池总大小不变)
  - 译文 > 原文字节: append 到字符串池末尾, 改这条 entry 的 offset 字段
  - 其他未翻译 entry / 命令 / 数字 entry 完全不动
  - 不修改 first_tbl, 不修改 index_tbl 中除 name/text entry 之外的任何字节

支持容器:
  - BCS\\0 + GMS\\0  (老引擎): 内层重新 LZSS (invert=True), 外层重新 LZSS
  - TSV\\0 + TNK\\0  (新引擎): 内层用 Blowfish 重新加密 (key="TLibDefKey")

注入产物会更新 header 中:
  - unpackedSize (因 strpool 可能膨胀)
  - thirdSectionSize (= 新内层容器的字节数)

用法:
    python bcs_inject.py <orig.bcs|dir> <json.json|dir> -o out_dir
"""
import os
import sys
import re
import json
import struct
import argparse

from bcs_lzss import lzss_unpack, lzss_pack_literal


# ============================================================
# Blowfish 加密 (TSV 路径用)
# ============================================================
def blowfish_encrypt(data: bytes, key: bytes) -> bytes:
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
        out[:n] = cipher.encrypt(bytes(out[:n]))
    return bytes(out)


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
# 解原 .bcs (拿到 first_tbl / index_tbl / strpool / 原始结构)
# ============================================================
def parse_bcs_full(path: str):
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

    first_tbl_size = obj_cnt * 8
    second_tbl_size = obj_parts * 8
    first_tbl = unpacked[:first_tbl_size]
    index_tbl = unpacked[first_tbl_size:first_tbl_size + second_tbl_size]
    third = unpacked[first_tbl_size + second_tbl_size:]

    if is_tsv:
        # TNK header (12B) 保留, 之后 Blowfish
        tnk_header = third[:12]
        strpool = blowfish_decrypt(third[12:], b"TLibDefKey")
        gms_header = None
    else:
        # GMS header (16B) 保留, 之后 LZSS invert
        gms_header = third[:16]
        strpool = lzss_unpack(third, 16, body_size, invert=True)
        tnk_header = None

    return {
        'magic': magic[:3].decode(),
        'is_tsv': is_tsv,
        'obj_cnt': obj_cnt,
        'obj_mark': obj_mark,
        'obj_parts': obj_parts,
        'first_tbl': first_tbl,
        'index_tbl': bytearray(index_tbl),  # 可写
        'strpool': bytearray(strpool),       # 可写
        'tnk_header': tnk_header,
        'gms_header': gms_header,
    }


# ============================================================
# 编码翻译文本为 CP932
# ============================================================
def encode_text(s: str, encoding: str, context: str = "") -> bytes:
    try:
        return s.encode(encoding)
    except UnicodeEncodeError:
        bad = []
        for i, ch in enumerate(s):
            try:
                ch.encode(encoding)
            except UnicodeEncodeError:
                bad.append(f"[{i}]{ch!r}(U+{ord(ch):04X})")
        raise ValueError(
            f"译文无法编码为 {encoding} ({context}): {''.join(bad)}\n"
            f"  原文: {s!r}"
        )


# ============================================================
# 应用一条字符串替换 (A 方案)
# ============================================================
def apply_one_replacement(parsed, entry_off, orig_str_off, orig_bytes_count,
                          new_bytes, stats, label=""):
    """更新 parsed['index_tbl'] 和 parsed['strpool']
       entry_off: 在 index_tbl 中的字节偏移 (op 字段位置)
       orig_str_off: 原 strpool 偏移
       orig_bytes_count: 原 CP932 字节数 (不含 NUL)
       new_bytes: 译文 CP932 字节 (不含 NUL)
    """
    index_tbl = parsed['index_tbl']
    strpool = parsed['strpool']

    # 校验 op 还是 0x03
    op = struct.unpack_from('<I', index_tbl, entry_off)[0] & 0b11
    if op != 0x03:
        raise ValueError(f"{label}: entry_off=0x{entry_off:X} 的 op={op} 非 0x03, "
                         f"JSON 与原 .bcs 不匹配")
    cur_off = struct.unpack_from('<I', index_tbl, entry_off + 4)[0]
    if cur_off != orig_str_off:
        raise ValueError(f"{label}: entry_off=0x{entry_off:X} 当前 str_off=0x{cur_off:X} "
                         f"!= JSON 记录的 0x{orig_str_off:X}, JSON 与原 .bcs 不匹配")

    new_len = len(new_bytes)

    if new_len <= orig_bytes_count:
        # 原位覆盖, 末尾补 NUL (原本 NUL 已经在 orig_str_off + orig_bytes_count 位置)
        # strpool[orig_str_off : orig_str_off + orig_bytes_count + 1] 是 [文本 + NUL]
        # 我们写 [新文本 + NUL + 0填充 凑够 orig_bytes_count + 1 字节]
        slot_size = orig_bytes_count + 1  # 含 NUL 的总槽位
        new_slot = new_bytes + b'\x00' * (slot_size - new_len)
        strpool[orig_str_off:orig_str_off + slot_size] = new_slot
        # offset 不变
        stats['inplace'] += 1
    else:
        # append 到末尾
        # 保留原位置不动 (不破坏其他可能的引用 — 虽然实测无共享, 但稳妥)
        # 写入新串 + NUL
        new_off = len(strpool)
        strpool.extend(new_bytes)
        strpool.append(0)
        # 改 entry 的 offset 字段
        struct.pack_into('<I', index_tbl, entry_off + 4, new_off)
        stats['appended'] += 1
        stats['append_bytes'] += new_len + 1


# ============================================================
# 重新打包 .bcs
# ============================================================
def repack_bcs(parsed) -> bytes:
    first_tbl = parsed['first_tbl']
    index_tbl = bytes(parsed['index_tbl'])
    strpool = bytes(parsed['strpool'])

    # 第三段 (字符串池容器)
    if parsed['is_tsv']:
        # TNK header + Blowfish(strpool)
        # 先 pad 到 8 字节倍数 (用 0)
        pad_n = (-len(strpool)) & 7
        padded = strpool + b'\x00' * pad_n
        encrypted = blowfish_encrypt(padded, b"TLibDefKey")
        third = parsed['tnk_header'] + encrypted
    else:
        # GMS header + LZSS(strpool, invert=True)
        gms_inner = lzss_pack_literal(strpool, invert=True)
        third = parsed['gms_header'] + gms_inner

    # 完整解压后的内容
    body_size_new = len(third)
    unpacked_new = first_tbl + index_tbl + third
    unp_size_new = len(unpacked_new)

    # 外层 LZSS (无 invert)
    outer = lzss_pack_literal(unpacked_new, invert=False)

    # 重建 header
    magic = (b'TSV' if parsed['is_tsv'] else b'BCS') + b'\x00'
    obj_cnt = parsed['obj_cnt']
    obj_mark = parsed['obj_mark']
    obj_parts = parsed['obj_parts']

    header = magic + struct.pack('<5I',
                                 unp_size_new,
                                 obj_cnt,
                                 obj_mark,
                                 obj_parts,
                                 body_size_new)
    return header + outer


# ============================================================
# 注入主流程
# ============================================================
def load_json_with_recovery(json_path):
    """读 JSON, 报错时定位行号并打印上下文; 自动清理已知非法控制字符"""
    with open(json_path, 'rb') as f:
        raw = f.read()
    # 先试一次原样解析
    try:
        return json.loads(raw.decode('utf-8'))
    except json.JSONDecodeError as e:
        pass

    text = raw.decode('utf-8', errors='replace')
    lines = text.split('\n')

    # 扫所有控制字符 (JSON 不允许 0x00-0x1F 除了 \r\n\t, \x7F 也不允许字符串内出现裸字节)
    # JSON 字符串里实际允许的: 普通字符 + 转义形式. 裸的 \x00-\x1F 都非法.
    ctrl_pattern = re.compile(rb'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')
    bad = []
    for ln_idx, line in enumerate(lines, 1):
        line_b = line.encode('utf-8', errors='replace')
        for m in ctrl_pattern.finditer(line_b):
            bad.append((ln_idx, m.start(), m.group()[0]))

    if bad:
        print(f"  [!] 发现 {len(bad)} 处非法控制字符 (JSON 不允许裸 0x00-0x1F):", file=sys.stderr)
        for ln, col, b in bad[:10]:
            ctx = lines[ln - 1] if ln - 1 < len(lines) else ''
            print(f"      line {ln} col {col}: 0x{b:02X}  上下文: {ctx[:80]!r}",
                  file=sys.stderr)
        if len(bad) > 10:
            print(f"      ... 共 {len(bad)} 处", file=sys.stderr)
        # 尝试自动清理后重试
        print(f"  [!] 自动剔除控制字符后重试...", file=sys.stderr)
        cleaned = ctrl_pattern.sub(b'', raw)
        try:
            return json.loads(cleaned.decode('utf-8'))
        except json.JSONDecodeError as e2:
            raise RuntimeError(
                f"JSON 解析失败 (清理控制字符后仍失败): {e2}\n"
                f"  原错误也定位过 {len(bad)} 个控制字符\n"
                f"  请手动检查 {json_path} 的内容"
            )
    else:
        # 不是控制字符问题, 重新抛原错并补充上下文
        try:
            json.loads(raw.decode('utf-8'))
        except json.JSONDecodeError as e:
            ln = e.lineno
            ctx = lines[ln - 1] if ln - 1 < len(lines) else ''
            raise RuntimeError(
                f"JSON 解析失败: {e}\n"
                f"  line {ln} col {e.colno}: {ctx[:120]!r}"
            )


def inject_one(bcs_path, json_path, out_path, verbose, encoding='cp932'):
    parsed = parse_bcs_full(bcs_path)
    items = load_json_with_recovery(json_path)

    stats = {'inplace': 0, 'appended': 0, 'append_bytes': 0,
             'skipped_unchanged': 0, 'name_replaced': 0, 'text_replaced': 0}

    for idx, item in enumerate(items):
        meta = item.get('_meta', {})
        row = meta.get('row', '?')
        # text
        text_ent = meta.get('text_entry_off')
        text_off = meta.get('text_str_off')
        text_orig = meta.get('text_orig_bytes', 0)
        new_text = item.get('message', '')
        # 没改就跳过
        # (我们没存 src_msg 校验, 只比"译文是否为空"是不安全的;
        #  这里干脆: 只要 message 字段存在, 就照常写入; 即使等于原文也无害)
        if text_ent is None or text_off is None:
            print(f"  [warn] item#{idx} row={row} 缺 text_entry_off, 跳过", file=sys.stderr)
            continue
        try:
            new_bytes = encode_text(new_text, encoding, f"row={row} %text%")
        except ValueError as e:
            print(f"  [FAIL] {e}", file=sys.stderr)
            return False
        apply_one_replacement(parsed, text_ent, text_off, text_orig, new_bytes,
                              stats, label=f"row={row} %text%")
        stats['text_replaced'] += 1

        # name (可选)
        name_ent = meta.get('name_entry_off')
        if name_ent is not None:
            name_off = meta.get('name_str_off')
            name_orig = meta.get('name_orig_bytes', 0)
            new_name = item.get('name', '')
            if not new_name:
                # 译文清空了 name 字段 -> 写空串 (原位)
                new_name_bytes = b''
            else:
                try:
                    new_name_bytes = encode_text(new_name, encoding, f"row={row} %name%")
                except ValueError as e:
                    print(f"  [FAIL] {e}", file=sys.stderr)
                    return False
            apply_one_replacement(parsed, name_ent, name_off, name_orig, new_name_bytes,
                                  stats, label=f"row={row} %name%")
            stats['name_replaced'] += 1

    # 重打包
    new_data = repack_bcs(parsed)
    with open(out_path, 'wb') as f:
        f.write(new_data)

    orig_size = os.path.getsize(bcs_path)
    new_size = len(new_data)

    if verbose:
        print(f"[OK]   {bcs_path}")
        print(f"       text={stats['text_replaced']}  name={stats['name_replaced']}  "
              f"inplace={stats['inplace']}  appended={stats['appended']} "
              f"(+{stats['append_bytes']} B)")
        print(f"       size: {orig_size} -> {new_size} "
              f"({(new_size/orig_size - 1)*100:+.1f}%)")
    else:
        print(f"[OK]   {bcs_path} -> {out_path}  "
              f"(text={stats['text_replaced']} name={stats['name_replaced']} "
              f"size {orig_size}->{new_size})")
    return True


# ============================================================
# 主入口
# ============================================================
def main():
    ap = argparse.ArgumentParser(
        description="Tanuki/Kaeru/Rune .bcs 文本注入器 (A 方案: 零风险原位+append)")
    ap.add_argument('bcs_input', help="原 .bcs 文件或目录")
    ap.add_argument('json_input', help="译文 .json 文件或目录")
    ap.add_argument('-o', '--output', required=True, help="输出目录")
    ap.add_argument('--overwrite', action='store_true')
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--encoding', default='cp932',
                    help="译文编码 (默认 cp932; 中文汉化引擎打 GBK leadbyte patch 后用 gbk)")
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)

    bcs_is_dir = os.path.isdir(args.bcs_input)
    json_is_dir = os.path.isdir(args.json_input)

    if bcs_is_dir != json_is_dir:
        print("错误: bcs_input 与 json_input 必须同为文件或同为目录")
        sys.exit(1)

    if not bcs_is_dir:
        out_path = os.path.join(args.output, os.path.basename(args.bcs_input))
        if not args.overwrite and os.path.exists(out_path):
            print(f"[skip] {out_path} 已存在")
            return
        inject_one(args.bcs_input, args.json_input, out_path, args.verbose, args.encoding)
        return

    # 批量
    bcs_files = sorted(fn for fn in os.listdir(args.bcs_input)
                       if fn.lower().endswith('.bcs'))
    ok = fail = skipped = 0
    for fn in bcs_files:
        base = os.path.splitext(fn)[0]
        if base.lower() in ('_emote', 'emote'):
            # emote 直接拷贝
            src = os.path.join(args.bcs_input, fn)
            dst = os.path.join(args.output, fn)
            with open(src, 'rb') as fi, open(dst, 'wb') as fo:
                fo.write(fi.read())
            if args.verbose:
                print(f"[copy] {fn} (emote 文件)")
            continue

        bcs_path = os.path.join(args.bcs_input, fn)
        json_path = os.path.join(args.json_input, base + '.json')
        out_path = os.path.join(args.output, fn)

        if not os.path.exists(json_path):
            if args.verbose:
                print(f"[skip] {fn}: 无对应 JSON, 直接拷贝原文件")
            with open(bcs_path, 'rb') as fi, open(out_path, 'wb') as fo:
                fo.write(fi.read())
            skipped += 1
            continue

        if not args.overwrite and os.path.exists(out_path):
            print(f"[skip] {out_path} 已存在")
            skipped += 1
            continue

        try:
            success = inject_one(bcs_path, json_path, out_path, args.verbose, args.encoding)
            if success:
                ok += 1
            else:
                fail += 1
        except Exception as e:
            print(f"[FAIL] {fn}: {e}")
            fail += 1

    print(f"\n完成: {ok} 成功, {fail} 失败, {skipped} 跳过, 共 {len(bcs_files)} 个文件")


if __name__ == '__main__':
    main()
