#!/usr/bin/env python3
"""
scn_inject.py - Seraph引擎 ScnPac 文本注入

用法:
  等长注入(安全): python scn_inject.py SCNPAC.DAT texts.json -o SCNPAC_new.DAT --fixed
  变长注入:       python scn_inject.py SCNPAC.DAT texts.json -o SCNPAC_new.DAT
  写回修正:       python scn_inject.py --apply-fix fix.json texts.json -o texts_fixed.json

等长模式(--fixed):
  每个fragment保持原始字节长度, 长则截断, 短则\\0 padding。
  所有偏移不变, 零风险。
  被截断的句子导出到 fix.json, 手动缩短后用 --apply-fix 写回。
"""

import struct
import sys
import os
import json
import seraph_lz


def read_scnpac(path):
    with open(path, 'rb') as f:
        data = f.read()
    count = struct.unpack_from('<I', data, 0)[0]
    offsets = [struct.unpack_from('<I', data, 4 + i * 4)[0] for i in range(count + 1)]
    return count, offsets, data


def write_scnpac(path, count, entries, tail):
    header_size = 4 + (count + 1) * 4
    current_offset = header_size
    offsets = []
    for e in entries:
        offsets.append(current_offset)
        current_offset += len(e)
    offsets.append(current_offset)

    out = bytearray()
    out.extend(struct.pack('<I', count))
    for off in offsets:
        out.extend(struct.pack('<I', off))
    for e in entries:
        out.extend(e)
    out.extend(tail)

    with open(path, 'wb') as f:
        f.write(out)
    return len(out)


def inject_entry_varlen(dec, replacements):
    """变长注入"""
    result = bytearray()
    i = 0
    while i < len(dec):
        if i in replacements:
            new_raw = replacements[i]
            result.append(0x00)
            result.extend(new_raw)
            result.append(0x00)
            i += 1
            while i < len(dec) and dec[i] != 0x00:
                i += 1
            i += 1
        else:
            result.append(dec[i])
            i += 1
    return bytes(result)


def inject_entry_fixed(dec, replacements):
    """等长注入: 每个fragment保持原始字节长度"""
    result = bytearray(dec)
    truncated = []

    for offset, new_raw in replacements.items():
        text_start = offset + 1
        text_end = text_start
        while text_end < len(dec) and dec[text_end] != 0x00:
            text_end += 1
        orig_len = text_end - text_start

        if len(new_raw) <= orig_len:
            result[text_start:text_start + len(new_raw)] = new_raw
            result[text_start + len(new_raw):text_end] = b'\x00' * (orig_len - len(new_raw))
        else:
            # 截断, 但不在双字节字符中间切
            cut = new_raw[:orig_len]
            try:
                cut.decode('cp932')
            except (UnicodeDecodeError, ValueError):
                cut = cut[:-1]
            result[text_start:text_start + len(cut)] = cut
            if len(cut) < orig_len:
                result[text_start + len(cut):text_end] = b'\x00' * (orig_len - len(cut))
            truncated.append((offset, orig_len, len(new_raw)))

    return bytes(result), truncated


def build_replacements(texts, encoding, fixed_mode=False):
    """从JSON构建fragment替换表"""
    entry_replacements = {}
    for item in texts:
        eidx = item['_entry']
        if eidx not in entry_replacements:
            entry_replacements[eidx] = {}

        msg = item.get('message', '')
        frags = item.get('_frags', [])

        orig_merged = ''
        for frag in frags:
            orig_merged += bytes.fromhex(frag['raw_hex']).decode('cp932')

        if msg == orig_merged:
            for frag in frags:
                entry_replacements[eidx][frag['offset']] = bytes.fromhex(frag['raw_hex'])
        elif fixed_mode:
            # 等长: 把译文字节顺序填入各fragment槽位
            try:
                msg_raw = msg.encode(encoding)
            except UnicodeEncodeError:
                for frag in frags:
                    entry_replacements[eidx][frag['offset']] = bytes.fromhex(frag['raw_hex'])
                continue

            remaining = msg_raw
            for frag in frags:
                orig_raw = bytes.fromhex(frag['raw_hex'])
                orig_len = len(orig_raw)
                chunk = remaining[:orig_len]
                remaining = remaining[len(chunk):]

                if len(chunk) > 0 and encoding.lower() in ('cp932', 'shift_jis', 'gbk', 'gb2312', 'big5'):
                    try:
                        chunk.decode(encoding)
                    except (UnicodeDecodeError, ValueError):
                        chunk = chunk[:-1]

                entry_replacements[eidx][frag['offset']] = chunk
        else:
            # 变长
            if len(frags) == 1:
                try:
                    new_raw = msg.encode(encoding)
                except UnicodeEncodeError:
                    new_raw = bytes.fromhex(frags[0]['raw_hex'])
                entry_replacements[eidx][frags[0]['offset']] = new_raw
            else:
                for fi, frag in enumerate(frags):
                    if fi == 0:
                        try:
                            new_raw = msg.encode(encoding)
                        except UnicodeEncodeError:
                            new_raw = bytes.fromhex(frag['raw_hex'])
                    else:
                        new_raw = '\u3000'.encode(encoding)
                    entry_replacements[eidx][frag['offset']] = new_raw

    return entry_replacements


def apply_fix(texts_path, fix_path, output_path):
    """把fix.json中修正后的译文写回texts.json"""
    with open(texts_path, 'r', encoding='utf-8') as f:
        texts = json.load(f)
    with open(fix_path, 'r', encoding='utf-8') as f:
        fixes = json.load(f)

    fix_map = {item['id']: item['message'] for item in fixes}
    applied = 0
    for item in texts:
        if item['id'] in fix_map:
            item['message'] = fix_map[item['id']]
            applied += 1

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(texts, f, ensure_ascii=False, indent=2)
    print(f'写回完成: {applied} 条修正 → {output_path}')


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Seraph ScnPac 文本注入')
    parser.add_argument('scnpac', nargs='?', help='原始 ScnPac.Dat 路径')
    parser.add_argument('texts', help='翻译后的 JSON 路径')
    parser.add_argument('-o', '--output', default='SCNPAC_new.DAT', help='输出路径')
    parser.add_argument('-e', '--encoding', default='cp932', help='目标编码 (默认cp932)')
    parser.add_argument('--fixed', action='store_true', help='等长注入模式(安全)')
    parser.add_argument('--fix-json', default='fix.json', help='截断句子导出路径')
    parser.add_argument('--apply-fix', metavar='FIX_JSON', help='把fix.json写回texts.json')
    args = parser.parse_args()

    if args.apply_fix:
        apply_fix(args.texts, args.apply_fix, args.output)
        return

    if not args.scnpac:
        parser.error('需要指定 ScnPac.Dat 路径')

    count, offsets, data = read_scnpac(args.scnpac)
    with open(args.texts, 'r', encoding='utf-8') as f:
        texts = json.load(f)

    entry_replacements = build_replacements(texts, args.encoding, args.fixed)

    new_entries = []
    modified_count = 0
    all_truncated = []

    for idx in range(count):
        entry_data = data[offsets[idx]:offsets[idx + 1]]

        if idx in entry_replacements and len(entry_data) >= 8:
            dec_size = struct.unpack_from('<I', entry_data, 0)[0]
            if dec_size > 0 and dec_size <= 0x100000 and dec_size >= len(entry_data):
                try:
                    dec = seraph_lz.decompress(entry_data)
                    if len(dec) == dec_size:
                        if args.fixed:
                            new_dec, truncated = inject_entry_fixed(
                                dec, entry_replacements[idx])
                            for t_off, t_orig, t_new in truncated:
                                for item in texts:
                                    if item['_entry'] == idx:
                                        for frag in item['_frags']:
                                            if frag['offset'] == t_off:
                                                all_truncated.append({
                                                    'id': item['id'],
                                                    'message': item['message'],
                                                    'capacity': t_orig,
                                                    'needed': t_new,
                                                    'overflow': t_new - t_orig,
                                                })
                                                break
                        else:
                            new_dec = inject_entry_varlen(
                                dec, entry_replacements[idx])

                        new_comp = seraph_lz.compress(new_dec)
                        if len(new_comp) < len(entry_data):
                            new_comp += b'\x00' * (len(entry_data) - len(new_comp))
                        new_entries.append(new_comp)
                        modified_count += 1
                        continue
                except Exception as e:
                    print(f'  entry[{idx:3d}] 处理失败: {e}')

        new_entries.append(entry_data)

    tail_start = offsets[count]
    tail = data[tail_start:] if tail_start < len(data) else b''
    out_size = write_scnpac(args.output, count, new_entries, tail)

    print(f'\n注入完成: 修改 {modified_count} 个entry → {args.output} ({out_size} bytes)')

    if args.fixed and all_truncated:
        seen = set()
        unique = []
        for t in all_truncated:
            if t['id'] not in seen:
                seen.add(t['id'])
                unique.append(t)
        unique.sort(key=lambda x: -x['overflow'])

        with open(args.fix_json, 'w', encoding='utf-8') as f:
            json.dump(unique, f, ensure_ascii=False, indent=2)

        print(f'\n⚠ 截断 {len(unique)} 条 → {args.fix_json}')
        print(f'  最大溢出: +{unique[0]["overflow"]} bytes')
        for t in unique[:10]:
            print(f'    id={t["id"]:4d} +{t["overflow"]:3d}B ({t["capacity"]}→{t["needed"]}): {t["message"][:40]}')
        if len(unique) > 10:
            print(f'    ... 共 {len(unique)} 条')
        print(f'\n  修正后写回: python scn_inject.py --apply-fix {args.fix_json} {args.texts} -o texts_fixed.json')
    elif args.fixed:
        print(f'\n✅ 无截断')


if __name__ == '__main__':
    main()
