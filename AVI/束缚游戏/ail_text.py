#!/usr/bin/env python3
"""
ail_text_eqlen.py - AIL/BONDAGE 等长替换提取/注入工具 (路径C保底方案)

============================================================
设计哲学
============================================================

不分析字节码 VM,不识别"哪些 u16 是文本指针",
也不区分"文本"和"选项跳转目标"——只做一件事:

  把文本区里所有 cp932 字符串原地等长替换成 GBK 中文.

保证:
  1. 文本区总字节数不变 (不动)
  2. 每条字符串的起始 offset 不变 (不动)
  3. 字符串末尾 \0 位置不变 (不动)  
  4. 字节码区一字不动
  5. arr1 label 表一字不动
  6. 12B 头一字不动

代价:
  中文长度受原日文字节数限制 (cp932 的日文 1 字符 2B,GBK 中文也 2B,
  所以理论 1:1; 但日文常含半角假名/标点,中文常需补半角空格)

适用范围:
  纯叙述性文本 (旁白/台词/标题) — 100% 安全
  含选项跳转的文本块 — 也安全,因为我们只改"看起来像 cp932 字符"
  的字节,跳转字节 (通常是 0x00..0x1F 或 0xFF) 不会被识别为"可翻译"

============================================================
工作流
============================================================

1. extract: ail_text_eqlen.py extract <bin_dir> -o texts.json
   遍历目录里所有 *.bin,把"可翻译的"日文字符串提取出来,
   附带每条的 (file_id, offset, byte_len) 信息

2. 翻译: 编辑 texts.json 的 message 字段 (中文)

3. inject: ail_text_eqlen.py inject <bin_dir> texts.json -o out_dir/
   按 (file_id, offset) 把翻译写回每个 .bin 文件,
   超长截断、不足补空格,确保 byte_len 不变
"""

import os, sys, json, struct, argparse, glob


# ============================================================
# 字符串扫描
# ============================================================

def is_translatable(raw: bytes) -> bool:
    """判断这个 \\0 分隔块是不是包含日文的可翻译字符串"""
    if len(raw) < 2:
        return False
    try:
        s = raw.decode('cp932')
    except UnicodeDecodeError:
        return False
    # 必须含 cp932 全角字符 (>= U+3000)
    has_jp = any(ord(c) >= 0x3000 for c in s)
    if not has_jp:
        return False
    # 排除含控制字符的(可能是混在文本区的二进制数据,不是真文本)
    if any(0 < ord(c) < 0x20 and c not in '\r\n\t' for c in s):
        return False
    return True


def parse_bin(path: str):
    """解析单个 .bin (剧本子文件),返回 dict"""
    with open(path, 'rb') as f:
        d = f.read()
    if len(d) < 12:
        return None
    f4 = struct.unpack_from('<H', d, 4)[0]
    f6 = struct.unpack_from('<H', d, 6)[0]
    n = f4 >> 1
    arr1_end = 12 + n * 2
    data_start = arr1_end + f6
    if data_start > len(d):
        return None
    return {
        'data': d,
        'data_start': data_start,
        'text_blob': d[data_start:],
    }


def scan_strings(text_blob: bytes):
    """
    扫描文本区,返回所有 \0 分隔的 cp932 字符串块.
    每个 entry: {offset, byte_len, raw, decoded, translatable}
    """
    out = []
    i = 0
    while i < len(text_blob):
        if text_blob[i] == 0:
            i += 1
            continue
        end = text_blob.find(b'\x00', i)
        if end < 0:
            end = len(text_blob)
        raw = bytes(text_blob[i:end])
        entry = {
            'offset': i,
            'byte_len': len(raw),
            'raw_hex': raw.hex(),
            'translatable': False,
            'decoded': None,
        }
        try:
            decoded = raw.decode('cp932')
            entry['decoded'] = decoded
            entry['translatable'] = is_translatable(raw)
        except UnicodeDecodeError:
            pass
        out.append(entry)
        i = end + 1
    return out


# ============================================================
# 提取
# ============================================================

def extract(bin_dir: str, out_json: str):
    bin_files = sorted(glob.glob(os.path.join(bin_dir, '*.bin')))
    print(f'扫描 {len(bin_files)} 个 .bin 文件...')

    all_files = []
    total_translatable = 0
    total_strings = 0

    for path in bin_files:
        name = os.path.basename(path)
        info = parse_bin(path)
        if info is None:
            continue
        strings = scan_strings(info['text_blob'])
        translatable = [s for s in strings if s['translatable']]
        total_strings += len(strings)
        total_translatable += len(translatable)

        file_entry = {
            'file': name,
            'data_start': info['data_start'],
            'text_blob_size': len(info['text_blob']),
            'texts': [
                {
                    'offset': s['offset'],
                    'byte_len': s['byte_len'],
                    'orig': s['decoded'],
                    'message': s['decoded'],  # 翻译时改这里
                }
                for s in translatable
            ],
        }
        all_files.append(file_entry)

    out = {
        'version': 1,
        'mode': 'eqlen',
        'files': all_files,
    }
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f'[OK] 提取完成:')
    print(f'  文件数:       {len(all_files)}')
    print(f'  总字符串块:   {total_strings}')
    print(f'  可翻译块:     {total_translatable}')
    print(f'  -> {out_json}')


# ============================================================
# 注入
# ============================================================

def encode_eqlen(text: str, target_len: int, encoding: str = 'gbk') -> bytes:
    """
    把 text 编码成正好 target_len 字节.
    超长截断 (按字符向后截,避免半个汉字),不足末尾补 0x20 空格.
    返回的 bytes 不含末尾 \0 (\0 由调用方处理).
    """
    # 编码并按字符逐步截断
    encoded = b''
    truncated = False
    for i, ch in enumerate(text):
        try:
            ch_bytes = ch.encode(encoding)
        except UnicodeEncodeError:
            # 编不了就跳过(用 ? 代替也行,这里选择跳过保持稳健)
            ch_bytes = b'?'
        if len(encoded) + len(ch_bytes) > target_len:
            truncated = True
            break
        encoded += ch_bytes
    # 末尾补空格
    pad = target_len - len(encoded)
    encoded += b'\x20' * pad
    return encoded, truncated


def inject(bin_dir: str, json_path: str, out_dir: str):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if data.get('mode') != 'eqlen':
        print(f'[!] 警告: JSON mode={data.get("mode")} 不是 eqlen')

    os.makedirs(out_dir, exist_ok=True)
    n_files = 0
    n_texts = 0
    n_truncated = 0
    n_unchanged = 0

    for file_entry in data['files']:
        name = file_entry['file']
        src_path = os.path.join(bin_dir, name)
        if not os.path.exists(src_path):
            print(f'[!] 找不到 {name}, 跳过')
            continue
        with open(src_path, 'rb') as f:
            d = bytearray(f.read())
        data_start = file_entry['data_start']

        for tx in file_entry['texts']:
            off = tx['offset']
            byte_len = tx['byte_len']
            orig = tx['orig']
            new = tx['message']
            n_texts += 1

            if new == orig:
                n_unchanged += 1
                continue

            encoded, truncated = encode_eqlen(new, byte_len, 'gbk')
            if truncated:
                n_truncated += 1
                print(f'[!] {name} +{off}: 截断')
                print(f'    原文: {orig}')
                print(f'    译文: {new}')

            # 写回. 注意要写到 data_start + off 的绝对位置
            abs_off = data_start + off
            d[abs_off:abs_off + byte_len] = encoded

        out_path = os.path.join(out_dir, name)
        with open(out_path, 'wb') as f:
            f.write(d)
        n_files += 1

    print(f'[OK] 注入完成:')
    print(f'  写入文件数:   {n_files}')
    print(f'  总文本条目:   {n_texts}')
    print(f'  未修改:       {n_unchanged}')
    print(f'  截断警告:     {n_truncated}')
    print(f'  -> {out_dir}/')


# ============================================================
# 自检: round-trip 不修改测试
# ============================================================

def selftest(bin_dir: str):
    """提取->不修改->注入,验证文件完全一致"""
    import tempfile
    import filecmp

    tmpdir = tempfile.mkdtemp()
    json_path = os.path.join(tmpdir, 'texts.json')
    out_dir = os.path.join(tmpdir, 'out')

    print('[1/3] extract...')
    extract(bin_dir, json_path)
    print()
    print('[2/3] inject (no changes)...')
    inject(bin_dir, json_path, out_dir)
    print()
    print('[3/3] 对比...')

    bin_files = sorted(glob.glob(os.path.join(bin_dir, '*.bin')))
    diffs = 0
    for src in bin_files:
        name = os.path.basename(src)
        dst = os.path.join(out_dir, name)
        if not os.path.exists(dst):
            print(f'  {name}: MISSING')
            diffs += 1
            continue
        if not filecmp.cmp(src, dst, shallow=False):
            # 找差异字节
            with open(src,'rb') as f: a=f.read()
            with open(dst,'rb') as f: b=f.read()
            n_diff = sum(1 for x,y in zip(a,b) if x!=y)
            print(f'  {name}: DIFF ({n_diff} bytes)')
            diffs += 1
    if diffs == 0:
        print(f'[OK] 全部 {len(bin_files)} 个文件 bit-perfect')
    else:
        print(f'[FAIL] {diffs} 个文件有差异')


# ============================================================
# main
# ============================================================

def main():
    ap = argparse.ArgumentParser(description='AIL/BONDAGE 等长替换工具')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('extract')
    p1.add_argument('bin_dir')
    p1.add_argument('-o', '--out', default='texts.json')

    p2 = sub.add_parser('inject')
    p2.add_argument('bin_dir')
    p2.add_argument('json')
    p2.add_argument('-o', '--out', default='bin_out')

    p3 = sub.add_parser('selftest')
    p3.add_argument('bin_dir')

    args = ap.parse_args()
    if args.cmd == 'extract':
        extract(args.bin_dir, args.out)
    elif args.cmd == 'inject':
        inject(args.bin_dir, args.json, args.out)
    elif args.cmd == 'selftest':
        selftest(args.bin_dir)


if __name__ == '__main__':
    main()
