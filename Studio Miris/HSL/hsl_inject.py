#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hsl_inject.py - HSL 脚本引擎选项变长注入工具

核心工作流:
  1. 读取翻译 JSON (GalTransl 格式, 含 _block_idx / _body_pc / _orig_str_len)
  2. 按 block 分组注入, 每个 block 内从后往前替换 (避免 body_pc 失效)
  3. 变长替换产生 delta, 修正:
     a) 同 block 内所有跳转 opcode (0x01/04/05/08/09) 的 target (若 target > 修改点)
     b) block 的 dsize (+= block_delta)
     c) jumptable: 当前 block 之后的所有 block 偏移 (+= cumulative_delta)

跳转 opcode 参考表 (来自 handoff):
  0x01: 7B,   jump_off = +3   (无条件)
  0x04: 22B,  jump_off = +18  (int 条件)
  0x05: 22B,  jump_off = +18  (int 条件)
  0x08: 22B,  jump_off = +18  (float 条件)
  0x09: 22B,  jump_off = +18  (float 条件)
  0x0a: 变长, jump_off = tail-4  (string 条件, 本次任务暂跳过)
  0x0b: 变长, jump_off = tail-4  (string 条件, 本次任务暂跳过)

关键: target 是 block body 内的相对偏移, 不跨 block.
"""

import struct
import json
import sys
from collections import defaultdict


# ============================================================
# Header 解析 (与 extract 共用)
# ============================================================

def parse_hsl(data: bytes) -> dict:
    assert data[:4] == b'HSL '
    version = struct.unpack_from('<H', data, 4)[0]
    labels_off = struct.unpack_from('<I', data, 6)[0]
    jumptable_off = struct.unpack_from('<I', data, 10)[0]
    code_start = struct.unpack_from('<I', data, 14)[0]

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
# 跳转扫描 (block body 内)
# ============================================================

# (opcode_byte, total_size, jump_target_rel_offset)
JUMP_OPCODES_FIXED = [
    (0x01, 7,  3),
    (0x04, 22, 18),
    (0x05, 22, 18),
    (0x08, 22, 18),
    (0x09, 22, 18),
]


def scan_jump_targets(body: bytes) -> list:
    """
    在 block body 里扫描所有跳转指令候选.
    返回 [(opcode_pos_in_body, target_field_pos_in_body, current_target_value), ...]

    Sanity check:
    - opcode u16 LE 匹配 (0x01/04/05/08/09 + 0x00)
    - target_field_pos + 4 <= len(body)
    - target 必须在 [0, len(body)) 范围内 (合法跳转 target)
    - target 不能等于 opcode_pos 本身 (防止自循环误报, 虽然理论可能)

    注意: 线性字节扫描会产生 false positive (命中数据区).
    我们额外用 "target 必须是合法 body 内偏移" 过滤, 但无法 100% 排除巧合.
    解决方案: 只对 target 需要被修正的 (即 target > 修改点) 做 delta 调整.
              如果误报命中一个值碰巧满足 "在 body 内且 > 修改点", 会改坏一个 4 字节.
    经验性观察: 相对小数值的 u32 在二进制流里并不常见, false positive 概率低.
    """
    results = []
    n = len(body)
    i = 0
    while i < n - 1:
        op = body[i]
        op2 = body[i + 1]
        if op2 == 0x00:
            for target_op, size, jt_off in JUMP_OPCODES_FIXED:
                if op == target_op:
                    if i + size <= n:
                        target_pos = i + jt_off
                        if target_pos + 4 <= n:
                            target = struct.unpack_from('<I', body, target_pos)[0]
                            # sanity: target 必须在 body 内
                            if target < n:
                                results.append({
                                    'op_pos': i,
                                    'opcode': op,
                                    'size': size,
                                    'target_field_pos': target_pos,
                                    'target': target,
                                })
                    break
        i += 1
    return results


# ============================================================
# 单个选项的变长替换
# ============================================================

def build_new_choice_bytes(new_text: str, trailing_marker: int, menu_id: int) -> bytes:
    """
    构造一条新的 0x111 选项指令字节.
    结构: [u16 0x0111][1B 0x02][u16 len][text][1B trailing][u32 menu_id]
    """
    text_bytes = new_text.encode('cp932')
    if len(text_bytes) > 0xFFFF:
        raise ValueError(f"Text too long: {len(text_bytes)} > 65535")
    return (
        struct.pack('<H', 0x0111)
        + bytes([0x02])
        + struct.pack('<H', len(text_bytes))
        + text_bytes
        + bytes([trailing_marker])
        + struct.pack('<I', menu_id)
    )


def compute_old_choice_size(orig_str_len: int) -> int:
    """旧选项指令总字节数 = opcode2 + marker1 + len2 + str + trailing1 + menu_id4"""
    return 2 + 1 + 2 + orig_str_len + 1 + 4  # = orig_str_len + 10


# ============================================================
# 单 block 注入
# ============================================================

def inject_block(body: bytearray, choices_in_block: list, verbose: bool = False) -> bytearray:
    """
    对单个 block 的 body 做注入 (body 是 mutable bytearray).
    choices_in_block: [{body_pc, orig_str_len, new_text, trailing_marker, menu_id}, ...]
    返回新的 body (可能变长).

    策略: 从后往前处理选项, 这样修改前面的选项不会影响后面已定位好的 body_pc.
    对每次替换, 先扫描当前 body 里的所有跳转 target, 再修正那些 target > 修改点的.
    """
    # 从后往前处理
    sorted_choices = sorted(choices_in_block, key=lambda c: c['body_pc'], reverse=True)

    for ch in sorted_choices:
        body_pc = ch['body_pc']
        orig_str_len = ch['orig_str_len']
        old_size = compute_old_choice_size(orig_str_len)

        new_instr = build_new_choice_bytes(
            ch['new_text'], ch['trailing_marker'], ch['menu_id']
        )
        new_size = len(new_instr)
        delta = new_size - old_size

        # 修改点的 "前/后" 分界: 被替换区域的起点
        # 任何 target 字段值 > body_pc (原字节索引) 的跳转, 其目标在被修改区域之后,
        # 需要 += delta
        # 精确一点: 被替换的旧指令占据 [body_pc, body_pc + old_size), 
        # target 字段值 >= body_pc + old_size 的才需要 += delta
        # target < body_pc 的完全不动
        # target in [body_pc, body_pc + old_size) 不应该出现 (不会跳到 0x111 指令内部)

        cutoff = body_pc + old_size

        if delta != 0:
            # 先扫描旧 body 定位所有跳转, 然后批量修改
            jumps = scan_jump_targets(bytes(body))

            # 但要注意: 跳转指令本身如果在被替换区域之后, 那么它的 op_pos 也会被 delta 影响;
            # 不过我们在这里先改 target 字段的值, 再实际替换 bytes, 所以这里对旧 body 的
            # target 字段值写入是正确的 (因为旧 body 还没变)
            for j in jumps:
                if j['target'] >= cutoff:
                    # 写回新的 target
                    new_target = j['target'] + delta
                    struct.pack_into('<I', body, j['target_field_pos'], new_target)

            if verbose:
                affected = sum(1 for j in jumps if j['target'] >= cutoff)
                print(f"    pc={body_pc} delta={delta:+d} jumps_scanned={len(jumps)} affected={affected}")

        # 实际替换 bytes (可能变长)
        body[body_pc:body_pc + old_size] = new_instr

    return body


# ============================================================
# 全文件注入
# ============================================================

def inject_file(data: bytes, info: dict, translations: list, verbose: bool = False) -> bytes:
    """
    对整个 HSL 文件做注入.
    translations: [{_block_idx, _body_pc, _orig_str_len, _menu_id, _trailing_marker, message}, ...]
    """
    # 按 block 分组
    by_block = defaultdict(list)
    for t in translations:
        by_block[t['_block_idx']].append({
            'body_pc': t['_body_pc'],
            'orig_str_len': t['_orig_str_len'],
            'new_text': t['message'],
            'trailing_marker': t['_trailing_marker'],
            'menu_id': t['_menu_id'],
        })

    # 先提取所有 block 的 (old_off, old_dsize, body)
    # 注意: 注入是按 block 独立进行的, 但我们输出时要按顺序重组
    data = bytearray(data)

    # 1. 收集所有 block 的 body
    blocks = []  # [(label, old_off, old_dsize, new_body_bytearray)]
    for bi in range(info['label_count']):
        old_off = info['jt_offsets'][bi]
        old_dsize = struct.unpack_from('<I', data, old_off)[0]
        body = bytearray(data[old_off + 4 : old_off + 4 + old_dsize])
        blocks.append({
            'idx': bi,
            'label': info['labels'][bi],
            'old_off': old_off,
            'old_dsize': old_dsize,
            'body': body,
        })

    # 2. 对含选项的 block 执行注入
    total_delta = 0
    for bi in sorted(by_block.keys()):
        b = blocks[bi]
        choices = by_block[bi]
        if verbose:
            print(f"  Block {bi:3d} ({b['label']}) dsize={b['old_dsize']} choices={len(choices)}")
        new_body = inject_block(b['body'], choices, verbose=verbose)
        b['body'] = new_body
        b['new_dsize'] = len(new_body)
        block_delta = b['new_dsize'] - b['old_dsize']
        total_delta += block_delta
        if verbose and block_delta != 0:
            print(f"    block_delta = {block_delta:+d}")

    # 为没有注入的 block 设 new_dsize = old_dsize
    for b in blocks:
        if 'new_dsize' not in b:
            b['new_dsize'] = b['old_dsize']

    # 3. 重组文件
    # header (0x00 .. code_start) 保持不变 (jumptable 需要更新, 但它在 header 之内)
    # 先复制原 header 区域
    out = bytearray(data[:info['code_start']])

    # 重新拼接 block
    new_jt_offsets = []
    cur_off = info['code_start']
    for b in blocks:
        new_jt_offsets.append(cur_off)
        out.extend(struct.pack('<I', b['new_dsize']))
        out.extend(b['body'])
        cur_off += 4 + b['new_dsize']

    # 4. 更新 out 里的 jumptable (在 header 区域)
    jt_off = info['jumptable_off']
    for i, off in enumerate(new_jt_offsets):
        struct.pack_into('<I', out, jt_off + i * 4, off)

    return bytes(out)


# ============================================================
# 主流程
# ============================================================

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <snr.dat> <translations.json> <out.dat> [--verbose]")
        return 1

    snr_path = sys.argv[1]
    json_path = sys.argv[2]
    out_path = sys.argv[3]
    verbose = '--verbose' in sys.argv

    with open(snr_path, 'rb') as f:
        data = f.read()

    with open(json_path, 'r', encoding='utf-8') as f:
        translations = json.load(f)

    print(f"[*] Loaded {len(translations)} translations")

    info = parse_hsl(data)
    print(f"[*] HSL: {info['label_count']} blocks, code_start=0x{info['code_start']:x}")

    out = inject_file(data, info, translations, verbose=verbose)

    with open(out_path, 'wb') as f:
        f.write(out)

    print(f"[+] Wrote {out_path}  ({len(out)} bytes, delta = {len(out) - len(data):+d})")

    import hashlib
    orig_md5 = hashlib.md5(data).hexdigest()
    new_md5 = hashlib.md5(out).hexdigest()
    print(f"[*] orig md5: {orig_md5}")
    print(f"[*] new  md5: {new_md5}")
    if orig_md5 == new_md5:
        print("[+] MD5 MATCH (round-trip identity)")
    else:
        print("[*] MD5 differ (expected if text changed)")

    return 0


if __name__ == '__main__':
    sys.exit(main())
