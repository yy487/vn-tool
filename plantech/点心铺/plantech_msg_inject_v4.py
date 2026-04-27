#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plantech_msg_inject.py v4 — PLANTECH MESSAGE 文本注入

v4 相对 v3:
  - 支持 name_style='kagi' 的重建 (角色名「内容」)
  - 向后兼容 bracket / hero / None
  - 旧 JSON (无 name_style 字段) 自动回退到 v3 行为
  - 更清晰的校验错误报告

控制码: [n]=FFFC, [r]=FFFE, [c1/2/3]=FFFB/FA/F9, [xXX]兜底
"""
import argparse, json, os, re, struct, tempfile
from typing import List, Tuple

CTRL_TOKENS = {
    '[n]':  b'\xff\xfc',
    '[r]':  b'\xff\xfe',
    '[c1]': b'\xff\xfb',
    '[c2]': b'\xff\xfa',
    '[c3]': b'\xff\xf9',
}
HEX_TOKEN = re.compile(r'\[x([0-9a-fA-F]{2})\]')
TOKEN_RE  = re.compile(r'(\[n\]|\[r\]|\[c[123]\]|\[x[0-9a-fA-F]{2}\])')

SPECIAL_CHAR_MAP = {}  # 预留的字符替换表 (如 CP932 不支持的简中字符映射)


def text_to_bytes(text: str, entry_id: int) -> bytes:
    out = bytearray()
    for part in TOKEN_RE.split(text):
        if not part:
            continue
        if part in CTRL_TOKENS:
            out.extend(CTRL_TOKENS[part]); continue
        m = HEX_TOKEN.fullmatch(part)
        if m:
            out.append(int(m.group(1), 16)); continue
        s = part
        for k, v in SPECIAL_CHAR_MAP.items():
            s = s.replace(k, v)
        try:
            out.extend(s.encode('cp932'))
        except UnicodeEncodeError as e:
            raise ValueError(
                f'[id={entry_id}] CP932 编码失败: {s[e.start:e.end]!r} '
                f'(完整文本: {text[:40]!r}...)'
            )
    return bytes(out)


def rebuild_sentence(entry: dict) -> bytes:
    """根据 name_style 重建 sentence 字节"""
    name = entry.get('name')
    message = entry.get('message', '')
    meta = entry.get('_meta', {})
    prefix = meta.get('name_prefix', '')
    style = meta.get('name_style')  # 'kagi' / 'bracket' / 'hero' / None

    if not name:
        full = message
    elif style == 'kagi':
        # 角色名「内容」
        full = prefix + name + '「' + message + '」'
    elif style == 'hero':
        full = prefix + '＠＠＠' + message
    elif style == 'bracket':
        full = prefix + '【' + name + '】' + message
    else:
        # 旧 JSON 无 name_style: 按 name 值推断
        if name == '＠主人公':
            full = prefix + '＠＠＠' + message
        else:
            full = prefix + '【' + name + '】' + message

    return text_to_bytes(full, entry['id'])


def inject(json_path: str, out_dir: str, h_size: int = None) -> Tuple[bytes, bytes]:
    with open(json_path, 'r', encoding='utf-8') as f:
        entries = json.load(f)

    entries.sort(key=lambda e: (e['_meta']['block_idx'], e['_meta']['sent_idx']))

    # 分 block
    blocks: List[List[dict]] = []
    cur = -1
    for e in entries:
        bi = e['_meta']['block_idx']
        if bi != cur:
            blocks.append([]); cur = bi
        blocks[-1].append(e)

    # sent_idx 连续性校验
    for b_list in blocks:
        for i, e in enumerate(b_list):
            if e['_meta']['sent_idx'] != i:
                raise ValueError(
                    f"block {e['_meta']['block_idx']} sent_idx 不连续 "
                    f"(期望 {i}, 实际 {e['_meta']['sent_idx']})"
                )

    # 重建 BIN, 记录每个 sentence 的新起点绝对偏移
    new_bin = bytearray()
    sent_new_off: List[List[int]] = []
    for bi, b_list in enumerate(blocks):
        if bi > 0:
            new_bin.extend(b'\xff\xff')
        sent_new_off.append([])
        for si, e in enumerate(b_list):
            if si > 0:
                new_bin.extend(b'\xff\xfc')
            sent_new_off[bi].append(len(new_bin))
            new_bin.extend(rebuild_sentence(e))
        if b_list[-1]['_meta'].get('trailing_n'):
            new_bin.extend(b'\xff\xfc')

    # 重建 H: sentence 级槽写入 (支持块内锚点)
    if h_size is None:
        h_size = 999999 * 4
    new_h = bytearray(h_size)
    h_writes = 0
    h_inner = 0
    for bi, b_list in enumerate(blocks):
        for si, e in enumerate(b_list):
            for slot_info in e['_meta'].get('h_slots', []):
                if isinstance(slot_info, list):
                    slot = slot_info[0]
                    inner = slot_info[1] if len(slot_info) > 1 else 0
                else:
                    slot = slot_info
                    inner = 0
                if slot * 4 + 4 > h_size:
                    raise ValueError(f'slot {slot} 超出 H 大小 ({h_size}B)')
                target = sent_new_off[bi][si] + inner
                struct.pack_into('<I', new_h, slot * 4, target)
                h_writes += 1
                if inner > 0:
                    h_inner += 1

    os.makedirs(out_dir, exist_ok=True)
    out_h = os.path.join(out_dir, 'MESSAGE.H')
    out_bin = os.path.join(out_dir, 'MESSAGE.BIN')
    open(out_h, 'wb').write(new_h)
    open(out_bin, 'wb').write(new_bin)

    print(f'[OK] 注入完成')
    print(f'     blocks: {len(blocks)}, sentences: {len(entries)}')
    print(f'     BIN: {len(new_bin)} 字节 -> {out_bin}')
    print(f'     H:   {len(new_h)} 字节 ({h_writes} 槽写入, {h_inner} 块内锚点) -> {out_h}')
    return bytes(new_h), bytes(new_bin)


def verify(json_path: str, orig_h: str, orig_bin: str) -> None:
    orig_h_data = open(orig_h, 'rb').read()
    orig_bin_data = open(orig_bin, 'rb').read()
    with tempfile.TemporaryDirectory() as tmp:
        new_h, new_bin = inject(json_path, tmp, h_size=len(orig_h_data))

    if new_h == orig_h_data:
        print('[✓] MESSAGE.H 字节级一致')
    else:
        diff = sum(1 for a, b in zip(new_h, orig_h_data) if a != b)
        print(f'[✗] MESSAGE.H 差异 {diff} 字节')
        for i in range(min(len(new_h), len(orig_h_data))):
            if new_h[i] != orig_h_data[i]:
                slot = i // 4
                nv = struct.unpack_from('<I', new_h, slot*4)[0]
                ov = struct.unpack_from('<I', orig_h_data, slot*4)[0]
                print(f'     首差异 slot={slot}  new=0x{nv:x}  orig=0x{ov:x}')
                break

    if new_bin == orig_bin_data:
        print('[✓] MESSAGE.BIN 字节级一致')
    else:
        diff = sum(1 for a, b in zip(new_bin, orig_bin_data) if a != b)
        print(f'[✗] MESSAGE.BIN 差异 {diff} 字节')
        for i in range(min(len(new_bin), len(orig_bin_data))):
            if new_bin[i] != orig_bin_data[i]:
                print(f'     首差异 offset=0x{i:x}  new={new_bin[i]:02x}  orig={orig_bin_data[i]:02x}')
                ctx_n = new_bin[max(0,i-8):i+16].hex()
                ctx_o = orig_bin_data[max(0,i-8):i+16].hex()
                print(f'     new  ctx: {ctx_n}')
                print(f'     orig ctx: {ctx_o}')
                break


def main():
    ap = argparse.ArgumentParser(description='PLANTECH MESSAGE 文本注入 v4')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p_inj = sub.add_parser('inject', help='根据 JSON 生成新的 H + BIN')
    p_inj.add_argument('json_file')
    p_inj.add_argument('-o', '--output', default='out')
    p_inj.add_argument('--h-size', type=int, default=None,
                       help='H 文件字节数 (默认 3999996 = 999999 slot * 4)')
    p_ver = sub.add_parser('verify', help='round-trip 字节级一致性校验')
    p_ver.add_argument('json_file')
    p_ver.add_argument('orig_h')
    p_ver.add_argument('orig_bin')
    args = ap.parse_args()
    if args.cmd == 'inject':
        inject(args.json_file, args.output, h_size=args.h_size)
    else:
        verify(args.json_file, args.orig_h, args.orig_bin)


if __name__ == '__main__':
    main()
