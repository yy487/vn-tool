#!/usr/bin/env python3
"""
Line2 Engine MES Script Text Extractor
=======================================
用法: python mes_extract.py <input.mes> [output.json]

MES格式:
  整个文件LZSS压缩。解压后:
  - 字节码VM，文本以 01 + CP932字符串 + 00 嵌入
  - 提取所有含日文(SJIS双字节)的字符串
  - 输出GalTransl兼容JSON
"""

import struct
import json
import sys
import os


def lzss_decompress(src: bytes) -> bytes:
    """Line2 LZSS解压: 4KB窗口, init=0xFEE, flag bit1=literal bit0=ref"""
    window = bytearray(0x1000)
    win_pos = 0xFEE
    output = bytearray()
    src_pos = 0
    comp_size = len(src)
    flags = 0
    flag_bits = 0
    while src_pos < comp_size:
        if flag_bits == 0:
            flags = src[src_pos]; src_pos += 1; flag_bits = 8
        if flags & 1:
            if src_pos >= comp_size: break
            b = src[src_pos]; src_pos += 1
            output.append(b)
            window[win_pos] = b
            win_pos = (win_pos + 1) & 0xFFF
        else:
            if src_pos + 1 >= comp_size: break
            low = src[src_pos]; high = src[src_pos + 1]; src_pos += 2
            off = low | ((high & 0xF0) << 4)
            length = (high & 0x0F) + 3
            for k in range(length):
                b = window[(off + k) & 0xFFF]
                output.append(b)
                window[win_pos] = b
                win_pos = (win_pos + 1) & 0xFFF
        flags >>= 1
        flag_bits -= 1
    return bytes(output)


def is_cp932_lead(b):
    return (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xEF)


def is_cp932_trail(b):
    return (0x40 <= b <= 0x7E) or (0x80 <= b <= 0xFC)


def has_sjis_chars(data: bytes, min_count=2) -> bool:
    """检查字节序列是否包含足够多的SJIS双字节字符"""
    count = 0
    i = 0
    while i < len(data) - 1:
        if is_cp932_lead(data[i]) and is_cp932_trail(data[i + 1]):
            count += 1
            if count >= min_count:
                return True
            i += 2
        else:
            i += 1
    return False


def is_filename(s: str) -> bool:
    exts = ['.gcc', '.ogg', '.mes', '.wav', '.bmp', '.png', '.mid']
    return any(s.lower().endswith(ext) for ext in exts)


def extract_strings(decomp: bytes) -> list:
    """
    扫描解压后的MES数据，提取所有 01+CP932string+00 模式的日文文本
    返回: [(offset_in_decomp, text_str), ...]
    """
    results = []
    i = 0
    while i < len(decomp) - 2:
        if decomp[i] == 0x01:
            # 尝试读取null-terminated字符串
            j = i + 1
            valid = True
            while j < len(decomp):
                c = decomp[j]
                if c == 0x00:
                    break
                if is_cp932_lead(c):
                    if j + 1 < len(decomp) and is_cp932_trail(decomp[j + 1]):
                        j += 2
                    else:
                        valid = False; break
                elif 0x20 <= c <= 0x7E:
                    j += 1
                elif c == 0x0A:  # 换行
                    j += 1
                else:
                    valid = False; break

            if valid and j < len(decomp) and decomp[j] == 0x00 and j > i + 1:
                raw = decomp[i + 1:j]
                if has_sjis_chars(raw) and not is_filename(raw.decode('cp932', errors='replace')):
                    text = raw.decode('cp932', errors='replace')
                    results.append((i + 1, text))  # offset指向字符串首字节(跳过01)
                i = j + 1
                continue
        i += 1
    return results


def process_one(mes_path: str, json_path: str):
    """处理单个MES文件"""
    with open(mes_path, 'rb') as f:
        raw = f.read()

    decomp = lzss_decompress(raw)
    strings = extract_strings(decomp)

    entries = []
    for idx, (offset, text) in enumerate(strings):
        entries.append({
            "id": idx,
            "name": "",
            "message": text,
            "offset": offset
        })

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    print(f"  {os.path.basename(mes_path)}: {len(raw)}->{len(decomp)} bytes, {len(strings)} texts -> {os.path.basename(json_path)}")
    return len(strings)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.mes> [output.json]")
        print(f"       {sys.argv[0]} <mes_dir> <json_dir>    (batch mode)")
        sys.exit(1)

    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else None

    if os.path.isdir(src):
        # 批量模式
        out_dir = dst or (src.rstrip('/\\') + '_json')
        os.makedirs(out_dir, exist_ok=True)
        mes_files = sorted(f for f in os.listdir(src) if f.upper().endswith('.MES'))
        total_files = 0
        total_texts = 0
        for fn in mes_files:
            mes_path = os.path.join(src, fn)
            json_name = os.path.splitext(fn)[0] + '.json'
            json_path = os.path.join(out_dir, json_name)
            try:
                n = process_one(mes_path, json_path)
                total_files += 1
                total_texts += n
            except Exception as e:
                print(f"  ✗ {fn}: {e}")
        print(f"\nDone: {total_files}/{len(mes_files)} files, {total_texts} texts -> {out_dir}/")
    else:
        # 单文件模式
        json_path = dst or os.path.splitext(src)[0] + '.json'
        process_one(src, json_path)


if __name__ == '__main__':
    main()
