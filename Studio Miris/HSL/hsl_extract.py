#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hsl_extract.py - HSL 脚本引擎选项提取工具 (字节扫描方案)

目标: hadaka/HSL snr.dat 里的 211 个选项 (opcode 0x111)

方案:
  1. 解析 HSL header 拿到 275 个 block 的文件偏移
  2. 在每个 block body 里线性扫描 `11 01` 字节模式
  3. 对每个命中做 sanity check (string marker + 长度 + cp932 解码)
  4. 输出 GalTransl 兼容 JSON

0x111 选项指令的完整结构:
  [u16 0x0111]                ← opcode
  [1B  string_marker = 0x02]  ← 变长字符串标记
  [u16 str_len]
  [str_len bytes cp932 text]  ← 选项文本
  [1B  trailing_marker]       ← 通常 0x00
  [u32 menu_id]               ← 菜单系统 ID, 注入时不需要修改
总长 = 2 + 3 + str_len + 5 = str_len + 10 字节
"""

import struct
import json
import sys
from collections import defaultdict


# ============================================================
# HSL Header 解析
# ============================================================

def parse_hsl(data: bytes) -> dict:
    """解析 HSL 文件头, 返回 labels / jt_offsets / code_start"""
    assert data[:4] == b'HSL ', f"Not HSL file: magic={data[:4]!r}"

    version = struct.unpack_from('<H', data, 4)[0]
    labels_off = struct.unpack_from('<I', data, 6)[0]
    jumptable_off = struct.unpack_from('<I', data, 10)[0]
    code_start = struct.unpack_from('<I', data, 14)[0]

    # labels 区: [u16 src_namelen][src_name][u32 label_count][labels...]
    pos = labels_off
    src_namelen = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    src_name = data[pos:pos + src_namelen].rstrip(b'\x00').decode('ascii', 'replace')
    pos += src_namelen
    label_count = struct.unpack_from('<I', data, pos)[0]
    pos += 4

    labels = []
    for _ in range(label_count):
        ln = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        labels.append(data[pos:pos + ln].rstrip(b'\x00').decode('ascii', 'replace'))
        pos += ln

    # jumptable: 每个 label 对应 block 的文件绝对偏移
    jt_offsets = list(struct.unpack_from(f'<{label_count}I', data, jumptable_off))

    return {
        'version': version,
        'labels_off': labels_off,
        'jumptable_off': jumptable_off,
        'code_start': code_start,
        'src_name': src_name,
        'label_count': label_count,
        'labels': labels,
        'jt_offsets': jt_offsets,
    }


# ============================================================
# 0x111 选项字节扫描
# ============================================================

def is_printable_cp932(s: str) -> bool:
    """sanity check: cp932 解码后的字符串是否合理 (无控制字符)"""
    for c in s:
        o = ord(c)
        if o < 0x20 and c not in '\n\r\t':
            return False
    return True


def try_parse_choice(body: bytes, pos: int) -> dict | None:
    """
    在 body 的 pos 位置尝试按 0x111 选项结构解析.
    成功返回 choice 字典, 失败返回 None.
    """
    # 至少需要 2 (opcode) + 3 (marker+len) + 0 (text) + 5 (trailing+menu_id) = 10 B
    if pos + 10 > len(body):
        return None

    # opcode 2B = 0x11 0x01
    if body[pos] != 0x11 or body[pos + 1] != 0x01:
        return None

    # string marker
    marker = body[pos + 2]
    if marker != 0x02:
        # 选项几乎都是 marker 0x02. 其他 marker 极少见, 暂不处理.
        return None

    # string length
    str_len = struct.unpack_from('<H', body, pos + 3)[0]
    if str_len == 0 or str_len > 200:
        return None

    text_start = pos + 5
    text_end = text_start + str_len

    # 整条 0x111 指令的末尾: text + 1B trailing marker + 4B menu_id
    instr_end = text_end + 5
    if instr_end > len(body):
        return None

    text_bytes = bytes(body[text_start:text_end])

    # cp932 解码
    try:
        text = text_bytes.decode('cp932')
    except UnicodeDecodeError:
        return None

    # sanity: 无控制字符
    if not is_printable_cp932(text):
        return None

    # trailing marker (通常 0x00) + menu_id
    trailing_marker = body[text_end]
    menu_id = struct.unpack_from('<I', body, text_end + 1)[0]

    return {
        'body_pc': pos,
        'marker': marker,
        'str_len': str_len,
        'text_byte_offset': text_start,
        'text': text,
        'text_bytes': text_bytes,
        'trailing_marker': trailing_marker,
        'menu_id': menu_id,
        'total_size': instr_end - pos,  # = 2 + 3 + str_len + 5 = str_len + 10
    }


def extract_choices(data: bytes, info: dict) -> list:
    """
    逐 block 扫描 0x111 选项.
    返回 [{block_idx, block_label, body_pc, text, ...}, ...]
    """
    choices = []
    for bi, block_off in enumerate(info['jt_offsets']):
        dsize = struct.unpack_from('<I', data, block_off)[0]
        body_start = block_off + 4
        body_end = body_start + dsize
        body = data[body_start:body_end]
        label = info['labels'][bi]

        i = 0
        while i < len(body) - 9:
            if body[i] == 0x11 and body[i + 1] == 0x01:
                result = try_parse_choice(body, i)
                if result is not None:
                    choices.append({
                        'block_idx': bi,
                        'block_label': label,
                        'block_off': block_off,
                        'body_pc': result['body_pc'],
                        'str_len': result['str_len'],
                        'text': result['text'],
                        'menu_id': result['menu_id'],
                        'trailing_marker': result['trailing_marker'],
                        'total_size': result['total_size'],
                    })
                    # 跳过整条指令, 避免在 text 内重复匹配
                    i += result['total_size']
                    continue
            i += 1

    return choices


# ============================================================
# 输出 GalTransl JSON
# ============================================================

def to_galtransl(choices: list) -> list:
    """转换为 GalTransl 兼容格式 [{id, name, message}, ...]"""
    out = []
    for idx, c in enumerate(choices):
        out.append({
            'id': idx,
            'name': '',  # 选项无角色名
            'message': c['text'],
            # 额外字段 (GalTransl 会保留), 用于 inject 时定位
            '_block_idx': c['block_idx'],
            '_block_label': c['block_label'],
            '_body_pc': c['body_pc'],
            '_orig_str_len': c['str_len'],
            '_menu_id': c['menu_id'],
            '_trailing_marker': c['trailing_marker'],
        })
    return out


# ============================================================
# 主函数
# ============================================================

def main():
    if len(sys.argv) < 2:
        snr_path = 'snr.dat'
        json_path = 'snr_choices.json'
    else:
        snr_path = sys.argv[1]
        json_path = sys.argv[2] if len(sys.argv) > 2 else 'snr_choices.json'

    with open(snr_path, 'rb') as f:
        data = f.read()

    print(f"[*] File: {snr_path}  ({len(data)} bytes)")

    info = parse_hsl(data)
    print(f"[*] HSL version: {info['version']}")
    print(f"[*] src_name:    {info['src_name']!r}")
    print(f"[*] label_count: {info['label_count']}")
    print(f"[*] code_start:  0x{info['code_start']:x}")
    print(f"[*] first block: 0x{info['jt_offsets'][0]:x}")

    choices = extract_choices(data, info)
    print(f"\n[+] Extracted {len(choices)} choices")

    # 按 block 分组统计
    by_block = defaultdict(list)
    for c in choices:
        by_block[c['block_idx']].append(c)
    print(f"[+] Distributed across {len(by_block)} blocks")

    # 显示前 10 条做 sanity check
    print("\n[*] First 10 choices:")
    for i, c in enumerate(choices[:10]):
        print(f"  [{c['block_idx']:3d}] {c['block_label']:10s}: {c['text']}")

    # 输出 GalTransl JSON
    gt = to_galtransl(choices)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Wrote {json_path}")

    return choices


if __name__ == '__main__':
    main()
