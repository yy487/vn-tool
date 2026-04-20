#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plantech_msg_extract.py v2 — PLANTECH 引擎 MESSAGE.H + MESSAGE.BIN 文本提取

两层切分模型 (v2 修正):
  block: 用 0xFF 0xFF 切, 引擎随机访问单位, H 槽位指向 block 起点
  sentence: 用 0xFF 0xFC ([n]) 切, 显示/翻译单位, 一句话一个 ▼ 等待点击

每个 sentence 是一条 JSON 条目, 翻译就以 sentence 为粒度. 同一 block 内的
多个 sentence 共享 block_idx, 用 sent_idx 在 block 内排序.

控制码占位符:
  [n]  = 0xFF 0xFC  句末 (会被切走, 不出现在 message 字段里)
  [r]  = 0xFF 0xFE  行内换行 (保留在 message 字段里, 翻译时也保留)
  [c1] = 0xFF 0xFB
  [c2] = 0xFF 0xFA
  [c3] = 0xFF 0xF9
  [xXX] 兜底

用法:
  python plantech_msg_extract.py MESSAGE.H MESSAGE.BIN -o messages.json
"""

import argparse
import json
import re
import struct
from typing import List, Dict, Tuple, Optional


# ---------- BIN 切分: block ----------

def split_blocks(bin_data: bytes) -> List[Tuple[int, bytes]]:
    """按 0xFF 0xFF 切 BIN 成 block 列表. 返回 [(block_start_offset, raw), ...]"""
    ffff_pos = []
    i = 0
    n = len(bin_data)
    while i < n - 1:
        if bin_data[i] == 0xff and bin_data[i + 1] == 0xff:
            ffff_pos.append(i)
            i += 2
        else:
            i += 1

    blocks = []
    if not ffff_pos:
        return [(0, bin_data)]
    blocks.append((0, bin_data[:ffff_pos[0]]))
    for k in range(1, len(ffff_pos)):
        s = ffff_pos[k - 1] + 2
        blocks.append((s, bin_data[s:ffff_pos[k]]))
    last = ffff_pos[-1] + 2
    blocks.append((last, bin_data[last:]))
    return blocks


# ---------- block 内按 [n] 切 sentence ----------

def split_sentences(raw: bytes) -> Tuple[List[bytes], bool]:
    """
    把一个 block 的 raw 按 0xFF 0xFC ([n]) 切成 sentence 列表.
    返回 (sentences, has_trailing_n).
    has_trailing_n=True 表示原文末尾以 [n] 结束.
    """
    sentences = []
    i = 0
    start = 0
    n = len(raw)
    has_trailing = False
    while i < n - 1:
        if raw[i] == 0xff and raw[i + 1] == 0xfc:
            sentences.append(raw[start:i])
            i += 2
            start = i
            continue
        if 0x81 <= raw[i] <= 0x9f or 0xe0 <= raw[i] <= 0xfc:
            if i + 1 < n:
                i += 2
                continue
        i += 1
    if start < n:
        sentences.append(raw[start:])
    else:
        # start == n 意味着最后一字节是 [n] 之后没东西
        if sentences:
            has_trailing = True
        else:
            sentences.append(b'')
    return sentences, has_trailing


# ---------- 控制码 -> 占位符 ----------

def msg_bytes_to_text(raw: bytes) -> str:
    out = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == 0xff and i + 1 < n:
            nb = raw[i + 1]
            tag = {
                0xfc: '[n]',
                0xfe: '[r]',
                0xfb: '[c1]',
                0xfa: '[c2]',
                0xf9: '[c3]',
            }.get(nb, f'[x{nb:02x}]')
            out.append(tag)
            i += 2
            continue
        if (0x81 <= b <= 0x9f) or (0xe0 <= b <= 0xfc):
            if i + 1 < n:
                try:
                    out.append(raw[i:i + 2].decode('cp932'))
                except UnicodeDecodeError:
                    out.append(f'[x{b:02x}]')
                i += 2
                continue
        if 0x20 <= b < 0x80:
            out.append(chr(b))
            i += 1
            continue
        out.append(f'[x{b:02x}]')
        i += 1
    return ''.join(out)


# ---------- 角色名拆分 ----------

NAME_PATTERN = re.compile(r'^(\u3000?)【([^】]+)】(.*)$', re.S)
HERO_PATTERN = re.compile(r'^(\u3000?)＠＠＠(.*)$', re.S)


def try_split_name(text: str) -> Tuple[Optional[str], str, str]:
    m = NAME_PATTERN.match(text)
    if m:
        return m.group(2), m.group(3), m.group(1)
    m = HERO_PATTERN.match(text)
    if m:
        return '＠主人公', m.group(2), m.group(1)
    return None, text, ''


# ---------- 主流程 ----------

def extract(h_path: str, bin_path: str, out_json: str) -> None:
    h_data = open(h_path, 'rb').read()
    bin_data = open(bin_path, 'rb').read()

    blocks = split_blocks(bin_data)
    print(f'[INFO] BIN 大小: {len(bin_data)} 字节')
    print(f'[INFO] block 总数: {len(blocks)}')

    off_to_block = {off: idx for idx, (off, _) in enumerate(blocks)}

    n_slots = len(h_data) // 4
    block_h_slots: Dict[int, List[int]] = {}
    unmatched = 0
    for k in range(n_slots):
        v = struct.unpack_from('<I', h_data, k * 4)[0]
        if v == 0:
            continue
        if v in off_to_block:
            block_h_slots.setdefault(off_to_block[v], []).append(k)
        else:
            unmatched += 1
    if unmatched:
        print(f'[警告] {unmatched} 个 H 槽未命中任何 block 起点')

    entries = []
    sent_id = 0
    for b_idx, (b_off, b_raw) in enumerate(blocks):
        sentences, has_trailing = split_sentences(b_raw)
        for s_idx, s_raw in enumerate(sentences):
            text = msg_bytes_to_text(s_raw)
            name, message, prefix = try_split_name(text)
            entry = {
                'id': sent_id,
                'name': name,
                'message': message,
                '_meta': {
                    'block_idx': b_idx,
                    'sent_idx': s_idx,
                    'sent_count': len(sentences),
                    'name_prefix': prefix,
                    # 只把 H 槽挂在 block 的第一句上 (首句出现在 block 起点)
                    'h_slots': block_h_slots.get(b_idx, []) if s_idx == 0 else [],
                    # 末尾是否有 trailing [n] (只在最后一句标记)
                    'trailing_n': has_trailing if s_idx == len(sentences) - 1 else False,
                    'raw_hex': s_raw.hex(),
                }
            }
            entries.append(entry)
            sent_id += 1

    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    named = sum(1 for e in entries if e['name'])
    h_indexed = sum(1 for e in entries if e['_meta']['h_slots'])
    print(f'[OK] 提取完成: {len(entries)} 句 (来自 {len(blocks)} blocks)')
    print(f'     带角色名: {named}')
    print(f'     被 H 引用的 block 首句: {h_indexed}')
    print(f'     输出: {out_json}')


def main():
    ap = argparse.ArgumentParser(description='PLANTECH MESSAGE 文本提取 v2')
    ap.add_argument('h_file')
    ap.add_argument('bin_file')
    ap.add_argument('-o', '--output', default='messages.json')
    args = ap.parse_args()
    extract(args.h_file, args.bin_file, args.output)


if __name__ == '__main__':
    main()
