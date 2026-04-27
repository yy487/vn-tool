#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plantech_msg_extract.py v4 — PLANTECH MESSAGE 文本提取

v4 相对 v3:
  - 新增「角色名「内容」」识别 (PLANTECH 实际格式, 危ない百貨店 等)
  - 向后兼容 v2 【】 格式 和 ＠＠＠ 主人公
  - name 识别为纯便利性增强, round-trip 字节级一致仍成立
  - 更详细的统计日志

H 槽结构 (不变):
  每 10 个 slot 对应一个 MES 脚本 id, 槽值 = BIN 绝对偏移 (通常指向 block 起点)
  每条 sentence 记录 h_slots: [(h_slot, inner_off), ...], inner_off 支持块内锚点

控制码占位符: [n]=FFFC, [r]=FFFE, [c1/2/3]=FFFB/FA/F9, [xXX]兜底
"""
import argparse, json, re, struct
from typing import List, Dict, Tuple


def split_blocks(bin_data: bytes) -> List[Tuple[int, bytes]]:
    """按 FF FF 切分 block, 返回 [(abs_start_in_bin, block_bytes), ...]"""
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
    按 FF FC ([n]) 切分 sentence, 跳过 CP932 双字节范围
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
    """原始字节 -> 带控制码占位符的文本"""
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


# ---- 说话人识别 ----
# PLANTECH 实际格式: 角色名「内容」 (本游戏主要格式)
# 兼容旧格式: 【名】内容  和  ＠＠＠内容 (主人公)
KAGI_PATTERN = re.compile(r'^(\u3000?)([^「\n\[]{1,20})「(.+)」\s*$', re.S)
NAME_PATTERN = re.compile(r'^(\u3000?)【([^】]+)】(.*)$', re.S)
HERO_PATTERN = re.compile(r'^(\u3000?)＠＠＠(.*)$', re.S)


def try_split_name(text: str):
    """
    返回 (name, message, prefix, name_style)
      name_style: 'kagi' / 'bracket' / 'hero' / None
    """
    # 优先「」(本游戏主要格式)
    m = KAGI_PATTERN.match(text)
    if m:
        prefix, name, content = m.group(1), m.group(2), m.group(3)
        # 过滤掉包含控制码的 name (避免误判整句为名字)
        if '[' not in name and '」' not in name:
            return name, content, prefix, 'kagi'
    m = NAME_PATTERN.match(text)
    if m:
        return m.group(2), m.group(3), m.group(1), 'bracket'
    m = HERO_PATTERN.match(text)
    if m:
        return '＠主人公', m.group(2), m.group(1), 'hero'
    return None, text, '', None


def extract(h_path: str, bin_path: str, out_json: str) -> None:
    h_data = open(h_path, 'rb').read()
    bin_data = open(bin_path, 'rb').read()

    # H 文件合法性: 必须是 4 字节对齐
    if len(h_data) % 4 != 0:
        print(f'[警告] MESSAGE.H 大小 {len(h_data)} 不是 4 的倍数')

    blocks = split_blocks(bin_data)

    # 预切每个 block 的 sentence
    block_sents = []
    block_has_trail = []
    for b_off, b_raw in blocks:
        sents, trail = split_sentences(b_raw)
        block_sents.append(sents)
        block_has_trail.append(trail)

    # H 槽解析: 每个非零 value 映射到 (block_idx, sent_idx, inner_off)
    # 槽值 = BIN 绝对偏移, 允许落在 block 任意 sentence 内 (含块内锚点)
    sent_h_slots: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}
    unmatched = 0
    unmatched_samples = []
    for k in range(len(h_data) // 4):
        v = struct.unpack_from('<I', h_data, k * 4)[0]
        if v == 0:
            continue
        located = False
        for bi, (b_off, b_raw) in enumerate(blocks):
            b_end = b_off + len(b_raw)
            if b_off <= v <= b_end:
                rel = v - b_off
                sents = block_sents[bi]
                for si, (ss, sb) in enumerate(sents):
                    s_end = ss + len(sb)
                    if ss <= rel <= s_end:
                        inner = rel - ss
                        sent_h_slots.setdefault((bi, si), []).append((k, inner))
                        located = True
                        break
                if not located:
                    # 落在 FF FC 的 2 字节间隙 -> 归属下一句 inner=0
                    for si in range(len(sents) - 1):
                        ss, sb = sents[si]
                        gap_start = ss + len(sb)
                        if gap_start < rel < gap_start + 2:
                            sent_h_slots.setdefault((bi, si + 1), []).append((k, 0))
                            located = True
                            break
                break
        if not located:
            unmatched += 1
            if len(unmatched_samples) < 5:
                unmatched_samples.append((k, v))

    if unmatched:
        print(f'[警告] {unmatched} 个 H 槽无法映射 (将在注入时丢失)')
        for k, v in unmatched_samples:
            print(f'         slot[{k}] = 0x{v:x}')

    # 输出 entries
    entries = []
    sent_id = 0
    style_stat = {'kagi': 0, 'bracket': 0, 'hero': 0, None: 0}
    for bi, sents in enumerate(block_sents):
        for si, (ss, sb) in enumerate(sents):
            text = msg_bytes_to_text(sb)
            name, message, prefix, style = try_split_name(text)
            style_stat[style] = style_stat.get(style, 0) + 1
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
                    'name_style': style,
                    'h_slots': [[s, o] for s, o in slots],
                    'trailing_n': block_has_trail[bi] if si == len(sents) - 1 else False,
                    'raw_hex': sb.hex(),
                }
            })
            sent_id += 1

    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    total_slots = sum(len(e['_meta']['h_slots']) for e in entries)
    inner_slots = sum(1 for e in entries for s, o in e['_meta']['h_slots'] if o != 0)
    named = sum(1 for e in entries if e['name'])
    print(f'[OK] 提取完成: {len(entries)} 句 (来自 {len(blocks)} blocks)')
    print(f'     带角色名: {named}  '
          f"「」={style_stat.get('kagi',0)}  "
          f"【】={style_stat.get('bracket',0)}  "
          f"主人公={style_stat.get('hero',0)}  "
          f"无={style_stat.get(None,0)}")
    print(f'     H 槽映射: {total_slots} 总 / {inner_slots} 块内锚点 (inner_off>0)')
    print(f'     输出: {out_json}')


def main():
    ap = argparse.ArgumentParser(description='PLANTECH MESSAGE 文本提取 v4')
    ap.add_argument('h_file', help='MESSAGE.H 偏移表')
    ap.add_argument('bin_file', help='MESSAGE.BIN 文本数据')
    ap.add_argument('-o', '--output', default='messages.json')
    args = ap.parse_args()
    extract(args.h_file, args.bin_file, args.output)


if __name__ == '__main__':
    main()
