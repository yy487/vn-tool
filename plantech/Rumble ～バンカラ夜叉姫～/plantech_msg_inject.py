#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plantech_msg_inject.py v2 — PLANTECH MESSAGE 文本注入

注入流程 (匹配 v2 提取器的 block/sentence 两层模型):
  1. 按 block_idx + sent_idx 排序
  2. 同 block_idx 的 sentence 按 sent_idx 顺序拼接, 中间用 [n] 分隔
     (最后一句之后是否带 [n] 由原文是否有尾段决定: sent_count 与实际 split
      结果对得上即可)
  3. block 之间用 0xFF 0xFF 分隔
  4. 重建 H: 全零, 每个 block 首句的 h_slots 写入 block 新偏移
  5. 输出 MESSAGE.H + MESSAGE.BIN

用法:
  inject:  python plantech_msg_inject.py inject messages.json -o out_dir/
  verify:  python plantech_msg_inject.py verify messages.json MESSAGE.H MESSAGE.BIN
"""

import argparse
import json
import os
import re
import struct
import sys
import tempfile
from typing import List, Tuple


CTRL_TOKENS = {
    '[n]':  b'\xff\xfc',
    '[r]':  b'\xff\xfe',
    '[c1]': b'\xff\xfb',
    '[c2]': b'\xff\xfa',
    '[c3]': b'\xff\xf9',
}
HEX_TOKEN = re.compile(r'\[x([0-9a-fA-F]{2})\]')
TOKEN_RE = re.compile(r'(\[n\]|\[r\]|\[c[123]\]|\[x[0-9a-fA-F]{2}\])')

SPECIAL_CHAR_MAP = {
    # 翻译时按需补
}


def text_to_bytes(text: str, entry_id: int) -> bytes:
    out = bytearray()
    parts = TOKEN_RE.split(text)
    for part in parts:
        if not part:
            continue
        if part in CTRL_TOKENS:
            out.extend(CTRL_TOKENS[part])
            continue
        m = HEX_TOKEN.fullmatch(part)
        if m:
            out.append(int(m.group(1), 16))
            continue
        s = part
        for k, v in SPECIAL_CHAR_MAP.items():
            s = s.replace(k, v)
        try:
            out.extend(s.encode('cp932'))
        except UnicodeEncodeError as e:
            bad = s[e.start:e.end]
            raise ValueError(
                f'[id={entry_id}] CP932 编码失败: {bad!r} '
                f'(请加入 SPECIAL_CHAR_MAP)'
            )
    return bytes(out)


def rebuild_sentence(entry: dict) -> bytes:
    """从 entry 重建一个 sentence 的字节 (不含尾部 [n], 不含前置 ffff)."""
    name = entry.get('name')
    message = entry.get('message', '')
    prefix = entry.get('_meta', {}).get('name_prefix', '')
    if name == '＠主人公':
        full = prefix + '＠＠＠' + message
    elif name:
        full = prefix + '【' + name + '】' + message
    else:
        full = message
    return text_to_bytes(full, entry['id'])


def inject(json_path: str, out_dir: str) -> Tuple[bytes, bytes]:
    with open(json_path, 'r', encoding='utf-8') as f:
        entries = json.load(f)

    # 按 block_idx + sent_idx 排序
    entries.sort(key=lambda e: (e['_meta']['block_idx'], e['_meta']['sent_idx']))

    # 按 block 分组
    blocks: List[List[dict]] = []
    cur_block = -1
    for e in entries:
        b_idx = e['_meta']['block_idx']
        if b_idx != cur_block:
            blocks.append([])
            cur_block = b_idx
        blocks[-1].append(e)

    # 校验 sent_idx 在每个 block 内连续从 0 开始
    for b_list in blocks:
        for i, e in enumerate(b_list):
            if e['_meta']['sent_idx'] != i:
                raise ValueError(
                    f"block {e['_meta']['block_idx']} sent_idx 不连续 "
                    f"(期望 {i}, 实际 {e['_meta']['sent_idx']})"
                )

    # 重建 BIN
    new_bin = bytearray()
    block_offsets: List[int] = []  # block_idx -> 新偏移
    for b_idx, b_list in enumerate(blocks):
        if b_idx > 0:
            new_bin.extend(b'\xff\xff')
        block_offsets.append(len(new_bin))

        # 同 block 的 sentences 用 [n] 分隔; 末尾是否再补 [n] 看 trailing_n
        for s_idx, e in enumerate(b_list):
            if s_idx > 0:
                new_bin.extend(b'\xff\xfc')
            new_bin.extend(rebuild_sentence(e))
        # 最后一句的 trailing_n
        if b_list[-1]['_meta'].get('trailing_n'):
            new_bin.extend(b'\xff\xfc')

    # 重建 H
    H_SLOT_COUNT = 999999
    new_h = bytearray(H_SLOT_COUNT * 4)
    h_writes = 0
    for b_idx, b_list in enumerate(blocks):
        # h_slots 只挂在 block 的第一句 (sent_idx==0)
        first = b_list[0]
        for slot in first['_meta']['h_slots']:
            if slot >= H_SLOT_COUNT:
                raise ValueError(f'slot {slot} 超出范围')
            struct.pack_into('<I', new_h, slot * 4, block_offsets[b_idx])
            h_writes += 1

    os.makedirs(out_dir, exist_ok=True)
    out_h = os.path.join(out_dir, 'MESSAGE.H')
    out_bin = os.path.join(out_dir, 'MESSAGE.BIN')
    with open(out_h, 'wb') as f:
        f.write(new_h)
    with open(out_bin, 'wb') as f:
        f.write(new_bin)

    print(f'[OK] 注入完成')
    print(f'     blocks: {len(blocks)}, sentences: {len(entries)}')
    print(f'     BIN: {len(new_bin)} 字节 -> {out_bin}')
    print(f'     H:   {len(new_h)} 字节 ({h_writes} 槽写入) -> {out_h}')
    return bytes(new_h), bytes(new_bin)


def verify(json_path: str, orig_h: str, orig_bin: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        new_h, new_bin = inject(json_path, tmp)

    orig_h_data = open(orig_h, 'rb').read()
    orig_bin_data = open(orig_bin, 'rb').read()

    if new_h == orig_h_data:
        print('[✓] MESSAGE.H 字节级一致')
    else:
        diff = sum(1 for a, b in zip(new_h, orig_h_data) if a != b)
        print(f'[✗] MESSAGE.H 差异 {diff} 字节 (new={len(new_h)} orig={len(orig_h_data)})')

    if new_bin == orig_bin_data:
        print('[✓] MESSAGE.BIN 字节级一致')
    else:
        diff = sum(1 for a, b in zip(new_bin, orig_bin_data) if a != b)
        print(f'[✗] MESSAGE.BIN 差异 {diff} 字节 (new={len(new_bin)} orig={len(orig_bin_data)})')
        for i in range(min(len(new_bin), len(orig_bin_data))):
            if new_bin[i] != orig_bin_data[i]:
                print(f'     首差异 @ 0x{i:x}: new={new_bin[i:i+8].hex()} orig={orig_bin_data[i:i+8].hex()}')
                break


def main():
    ap = argparse.ArgumentParser(description='PLANTECH MESSAGE 文本注入 v2')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_inj = sub.add_parser('inject')
    p_inj.add_argument('json_file')
    p_inj.add_argument('-o', '--output', default='out')

    p_ver = sub.add_parser('verify')
    p_ver.add_argument('json_file')
    p_ver.add_argument('orig_h')
    p_ver.add_argument('orig_bin')

    args = ap.parse_args()
    if args.cmd == 'inject':
        inject(args.json_file, args.output)
    else:
        verify(args.json_file, args.orig_h, args.orig_bin)


if __name__ == '__main__':
    main()
