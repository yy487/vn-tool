#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plantech_msg_extract.py v3 — PLANTECH MESSAGE 文本提取

v3 修正 (相对 v2):
  - H 槽映射改为 sentence 级, 支持 block 内部锚点 (如 FF FB 59 跳转目标)
  - 每条 sentence 携带 h_slots + 每个槽在 sentence 内的字节偏移 anchor_off
  - round-trip 保证 H + BIN 全字节一致

控制码占位符同 v2: [n]=FFFC, [r]=FFFE, [c1/2/3]=FFFB/FA/F9, [xXX]兜底
"""
import argparse, json, re, struct
from typing import List, Dict, Tuple, Optional


def split_blocks(bin_data: bytes) -> List[Tuple[int, bytes]]:
    ffff = []
    i, n = 0, len(bin_data)
    while i < n - 1:
        if bin_data[i] == 0xff and bin_data[i + 1] == 0xff:
            ffff.append(i); i += 2
        else:
            i += 1
    if not ffff:
        return [(0, bin_data)]
    blocks = [(0, bin_data[:ffff[0]])]
    for k in range(1, len(ffff)):
        s = ffff[k - 1] + 2
        blocks.append((s, bin_data[s:ffff[k]]))
    last = ffff[-1] + 2
    blocks.append((last, bin_data[last:]))
    return blocks


def split_sentences(raw: bytes) -> Tuple[List[Tuple[int, bytes]], bool]:
    """
    返回 ([(sent_start_in_block, sent_bytes), ...], has_trailing_n)
    """
    sents = []
    i, start, n = 0, 0, len(raw)
    has_trailing = False
    while i < n - 1:
        if raw[i] == 0xff and raw[i + 1] == 0xfc:
            sents.append((start, raw[start:i]))
            i += 2; start = i; continue
        if 0x81 <= raw[i] <= 0x9f or 0xe0 <= raw[i] <= 0xfc:
            if i + 1 < n:
                i += 2; continue
        i += 1
    if start < n:
        sents.append((start, raw[start:]))
    else:
        if sents:
            has_trailing = True
        else:
            sents.append((0, b''))
    return sents, has_trailing


def msg_bytes_to_text(raw: bytes) -> str:
    out = []
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0xff and i + 1 < n:
            nb = raw[i + 1]
            tag = {0xfc:'[n]',0xfe:'[r]',0xfb:'[c1]',0xfa:'[c2]',0xf9:'[c3]'}.get(nb, f'[x{nb:02x}]')
            out.append(tag); i += 2; continue
        if (0x81 <= b <= 0x9f) or (0xe0 <= b <= 0xfc):
            if i + 1 < n:
                try:
                    out.append(raw[i:i+2].decode('cp932'))
                except UnicodeDecodeError:
                    out.append(f'[x{b:02x}]')
                i += 2; continue
        if 0x20 <= b < 0x80:
            out.append(chr(b)); i += 1; continue
        out.append(f'[x{b:02x}]'); i += 1
    return ''.join(out)


NAME_PATTERN = re.compile(r'^(\u3000?)【([^】]+)】(.*)$', re.S)
HERO_PATTERN = re.compile(r'^(\u3000?)＠＠＠(.*)$', re.S)

def try_split_name(text: str):
    m = NAME_PATTERN.match(text)
    if m: return m.group(2), m.group(3), m.group(1)
    m = HERO_PATTERN.match(text)
    if m: return '＠主人公', m.group(2), m.group(1)
    return None, text, ''


def extract(h_path: str, bin_path: str, out_json: str) -> None:
    h_data = open(h_path, 'rb').read()
    bin_data = open(bin_path, 'rb').read()
    blocks = split_blocks(bin_data)

    # 预切每个 block 的 sentence, 建立 (abs_offset -> (block_idx, sent_idx, inner_off))
    # inner_off = 相对 sentence 起点的字节偏移 (0 = sentence 首字节)
    # abs_offset 允许等于 sentence 末尾 (sent_start+len), 表示紧跟 [n] 之后, 归到下一句 inner_off=0
    block_sents = []   # [[(start, bytes), ...], ...]
    block_has_trail = []
    for b_off, b_raw in blocks:
        sents, trail = split_sentences(b_raw)
        block_sents.append(sents)
        block_has_trail.append(trail)

    # H 槽解析: 每个非零 value 映射到 (block_idx, sent_idx, inner_off)
    # sent_h_slots[(block_idx, sent_idx)] = [(h_slot, inner_off), ...]
    sent_h_slots: Dict[Tuple[int,int], List[Tuple[int,int]]] = {}
    unmatched = 0
    for k in range(len(h_data) // 4):
        v = struct.unpack_from('<I', h_data, k * 4)[0]
        if v == 0: continue
        # 找所在 block
        located = False
        for bi, (b_off, b_raw) in enumerate(blocks):
            b_end = b_off + len(b_raw)
            if b_off <= v <= b_end:
                rel = v - b_off
                # 找所在 sentence
                sents = block_sents[bi]
                for si, (ss, sb) in enumerate(sents):
                    s_end = ss + len(sb)
                    # rel 落在 [ss, s_end] 区间 (含右端点 = 紧贴 [n] 前)
                    if ss <= rel <= s_end:
                        inner = rel - ss
                        sent_h_slots.setdefault((bi, si), []).append((k, inner))
                        located = True
                        break
                if not located:
                    # rel 落在 [n] 的 FFFC 2字节里 -> 归属下一句 inner=0
                    for si in range(len(sents) - 1):
                        ss, sb = sents[si]
                        gap_start = ss + len(sb)  # [n]开始
                        if gap_start < rel < gap_start + 2:
                            sent_h_slots.setdefault((bi, si+1), []).append((k, 0))
                            located = True; break
                break
        if not located:
            unmatched += 1

    if unmatched:
        print(f'[警告] {unmatched} 个 H 槽无法映射 (将在注入时丢失)')

    # 输出 entries
    entries = []
    sent_id = 0
    for bi, sents in enumerate(block_sents):
        for si, (ss, sb) in enumerate(sents):
            text = msg_bytes_to_text(sb)
            name, message, prefix = try_split_name(text)
            slots = sent_h_slots.get((bi, si), [])
            entries.append({
                'id': sent_id,
                'name': name,
                'message': message,
                '_meta': {
                    'block_idx': bi,
                    'sent_idx': si,
                    'sent_count': len(sents),
                    'name_prefix': prefix,
                    # 新结构: 每个槽记录 (h_slot, inner_off)
                    # inner_off=0 表示 sentence 起点 (最常见)
                    # inner_off>0 表示 sentence 内部锚点 (如 FB 59 后跳转目标)
                    'h_slots': [[s, o] for s, o in slots],
                    'trailing_n': block_has_trail[bi] if si == len(sents) - 1 else False,
                    'raw_hex': sb.hex(),
                }
            })
            sent_id += 1

    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    total_slots = sum(len(e['_meta']['h_slots']) for e in entries)
    inner_slots = sum(1 for e in entries for s,o in e['_meta']['h_slots'] if o != 0)
    named = sum(1 for e in entries if e['name'])
    print(f'[OK] 提取完成: {len(entries)} 句 (来自 {len(blocks)} blocks)')
    print(f'     带角色名: {named}')
    print(f'     H 槽映射: {total_slots} 总 / {inner_slots} 块内锚点 (inner_off>0)')
    print(f'     输出: {out_json}')


def main():
    ap = argparse.ArgumentParser(description='PLANTECH MESSAGE 文本提取 v3')
    ap.add_argument('h_file')
    ap.add_argument('bin_file')
    ap.add_argument('-o', '--output', default='messages.json')
    args = ap.parse_args()
    extract(args.h_file, args.bin_file, args.output)

if __name__ == '__main__':
    main()
