#!/usr/bin/env python3
"""
scn_extract.py - Seraph引擎 ScnPac 文本提取

用法: python scn_extract.py SCNPAC.DAT -o texts.json

从ScnPac.Dat中解包所有脚本entry → LZ解压 → 扫描VM opcode 0x00提取inline CP932文本
按opcode 0x15(WAIT_CLICK)自然分段, 合并连续文本片段为完整台词
"""

import struct
import sys
import os
import json
import seraph_lz


def is_cp932_text_start(data, pos):
    """检查pos处是否是CP932文本开头(lead byte)"""
    if pos >= len(data):
        return False
    b = data[pos]
    return (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC)


def scan_text_at(dec, i):
    """从dec[i+1]开始尝试读取一个CP932 null-terminated string
    返回 (end_pos, raw_bytes, text_str) 或 None
    end_pos 指向终止\\0的下一个字节
    """
    text_start = i + 1
    j = text_start
    has_jp = False

    while j < len(dec) and dec[j] != 0x00:
        b = dec[j]
        if (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xFC):
            if j + 1 >= len(dec):
                return None
            has_jp = True
            j += 2
        elif 0x20 <= b < 0x7F or b in (0x0A, 0x0D):
            j += 1
        else:
            return None

    if not has_jp or j >= len(dec) or dec[j] != 0x00:
        return None

    raw = bytes(dec[text_start:j])
    try:
        text = raw.decode('cp932')
        return (j + 1, raw, text)
    except Exception:
        return None


def extract_entry(dec):
    """从解压后脚本中提取对话行

    按 WAIT(0x15) / BREAK(0xFF) 分段, 合并连续文本片段
    捕获 NAME_REF(0x11) 获取角色名索引

    返回 [{'name_ref': int|None, 'fragments': [{'offset':int, 'raw':bytes, 'text':str}], 'message': str}]
    """
    # 先收集所有FE选择支的文本偏移范围, 提取时跳过
    # FE结构: [FE] [count:1B] [params:4B] [text1\0] [text2\0] ... [FF]
    choice_ranges = set()
    for ci in range(len(dec) - 6):
        if dec[ci] == 0xFE and 1 <= dec[ci + 1] <= 10:
            cnt = dec[ci + 1]
            # 跳过FE + count + 4字节参数 = 6字节
            cpos = ci + 6
            valid = True
            for _ in range(cnt):
                if cpos >= len(dec):
                    valid = False
                    break
                cend = dec.find(0, cpos)
                if cend < 0 or cend >= len(dec):
                    valid = False
                    break
                # 每段文本前面的\0位置(即cpos-1)可能被误认为opcode 0x00
                if cpos > 0:
                    choice_ranges.add(cpos - 1)
                cpos = cend + 1
            if valid and cpos < len(dec) and dec[cpos] == 0xFF:
                pass  # confirmed FE structure

    events = []
    i = 0
    while i < len(dec):
        if dec[i] == 0x15:
            events.append(('WAIT', i, None))
            i += 1
        elif dec[i] == 0x11 and i + 1 < len(dec):
            events.append(('NAME', i, dec[i + 1]))
            i += 2
        elif dec[i] == 0xFF:
            events.append(('BREAK', i, None))
            i += 1
        elif dec[i] == 0x00 and i + 1 < len(dec):
            if i in choice_ranges:
                i += 1  # 跳过选择支文本的\0
                continue
            result = scan_text_at(dec, i)
            if result:
                end, raw, text = result
                events.append(('TEXT', i, {'offset': i, 'raw': raw, 'text': text}))
                i = end
                continue
            i += 1
        else:
            i += 1

    # 按 WAIT/BREAK 合并文本片段
    lines = []
    cur_name = None
    cur_frags = []

    for typ, off, data in events:
        if typ == 'NAME':
            cur_name = data
        elif typ == 'TEXT':
            cur_frags.append(data)
        elif typ in ('WAIT', 'BREAK'):
            if cur_frags:
                merged = ''.join(f['text'] for f in cur_frags)
                if merged.strip():
                    lines.append({
                        'name_ref': cur_name,
                        'fragments': cur_frags,
                        'message': merged,
                    })
                cur_frags = []
                cur_name = None

    # 残留
    if cur_frags:
        merged = ''.join(f['text'] for f in cur_frags)
        if merged.strip():
            lines.append({
                'name_ref': cur_name,
                'fragments': cur_frags,
                'message': merged,
            })

    return lines


def read_scnpac(path):
    """读取ScnPac.Dat, 返回 (count, offsets, raw_data)"""
    with open(path, 'rb') as f:
        data = f.read()
    count = struct.unpack_from('<I', data, 0)[0]
    offsets = [struct.unpack_from('<I', data, 4 + i * 4)[0] for i in range(count + 1)]
    return count, offsets, data


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Seraph ScnPac 文本提取')
    parser.add_argument('scnpac', help='ScnPac.Dat 路径')
    parser.add_argument('-o', '--output', default='scn_texts.json', help='输出JSON路径')
    args = parser.parse_args()

    count, offsets, data = read_scnpac(args.scnpac)

    all_entries = []
    total_lines = 0

    for idx in range(count):
        entry_data = data[offsets[idx]:offsets[idx + 1]]
        if len(entry_data) < 8:
            continue

        # 尝试LZ解压
        dec_size = struct.unpack_from('<I', entry_data, 0)[0]
        if dec_size == 0 or dec_size > 0x100000 or dec_size < len(entry_data):
            continue

        try:
            dec = seraph_lz.decompress(entry_data)
        except Exception:
            continue

        if len(dec) != dec_size:
            continue

        lines = extract_entry(dec)
        if not lines:
            continue

        entry_out = []
        for line in lines:
            item = {}
            if line['name_ref'] is not None and line['name_ref'] != 255:
                item['name'] = f'[name_{line["name_ref"]}]'
            item['message'] = line['message']
            # 记录每个片段的偏移(注入时需要)
            item['_entry'] = idx
            item['_frags'] = [{'offset': f['offset'], 'raw_hex': f['raw'].hex()} for f in line['fragments']]
            entry_out.append(item)

        if entry_out:
            all_entries.extend(entry_out)
            total_lines += len(entry_out)
            print(f'  entry[{idx:3d}] → {len(entry_out):4d} lines')

    # 添加序号
    for i, item in enumerate(all_entries):
        item['id'] = i

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(all_entries, f, ensure_ascii=False, indent=2)

    print(f'\n提取完成: {total_lines} 条台词 → {args.output}')


if __name__ == '__main__':
    main()
