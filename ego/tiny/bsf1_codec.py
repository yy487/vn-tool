#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bsf1_codec.py  —  Studio e.go! / TwinWay BSF1 脚本反汇编底层模块

基于 tw.exe 逆向:
    FUN_00413021  标签查找  (定位 label table 结构)
    FUN_00413106  VM 主循环 (39 outer opcode + 18 group0 sub_op 消费规则)
    FUN_00416168  文本渲染  (default 分支读裸 CP932 cstring 直到 \0)
    FUN_00415403  read_u16
    FUN_0041544d  read_u32
    FUN_00415494  read_cstring

文件结构:
    +0x00   magic 'BSF1'
    +0x04   label_table: [asciz name][u32 offset] × N (空 name 终止)
                         bc_start = min(label.offset)
    +bc     bytecode: [u16 opcode] + per-op args
                      u16 < 0x27 → 已知 opcode, 按规则消费参数
                      u16 ≥ 0x27 → default, 回退 PC 读 cstring 作为文本
"""
import struct

MAGIC = b'BSF1'


# 每个 outer opcode 静态参数消费规则 (助记符, 参数格式)
# 格式字符:  'W'=u16(2B)  'L'=u32(4B)  'S'=cstring(变长\0)
OUTER_OPS = {
    0x00: ('GROUP0',    None),    # 特殊: 递归读 sub_op
    0x01: ('LOAD_EGA',  'S'),
    0x02: ('SPEAKER',   'S'),     # 设置说话人, "*"=继承
    0x03: ('WAIT',      ''),      # 换页
    0x04: ('BG',        'S+'),    # cstring, 首字符 '+' 时再读 LL
    0x05: ('FG1',       'S'),
    0x06: ('FX6',       'W'),
    0x07: ('FX7',       'W'),
    0x08: ('FX8',       'W'),
    0x09: ('FX9',       'W'),
    0x0A: ('DELAY',     'W'),
    0x0B: ('RET',       'S'),
    0x0C: ('JUMP',      'S'),
    0x0D: ('JUMP_IF_EQ', 'S'),
    0x0E: ('JUMP_IF_NE', 'S'),
    0x0F: ('JUMP_IF_LT', 'S'),
    0x10: ('JUMP_IF_GE', 'S'),
    0x11: ('CALL_SCRIPT', 'SS'),
    0x12: ('MENU',      '*N'),    # u16 n + n × cstring
    0x13: ('VAR_SET_IMM', 'WW'),
    0x14: ('VAR_SET_VAR', 'WW'),
    0x15: ('VAR_ADD',   'WW'),
    0x16: ('VAR_SUB',   'WW'),
    0x17: ('CMP_IMM',   'WW'),
    0x18: ('CMP_VAR',   'WW'),
    0x19: ('SELECT',    '*N'),
    0x1A: ('CALL_SCRIPT2', 'SS'),
    0x1B: ('FADE',      'WW'),
    0x1C: ('FONT',      'WW'),
    0x1D: ('NOP1D',     ''),
    0x1E: ('BGM',       'S'),
    0x1F: ('VOICE_WAIT', 'W'),
    0x20: ('FADEOUT',   'W'),
    0x21: ('OP21',      'WW'),
    0x22: ('VAR_READ',  'S'),
    0x23: ('VAR_WRITE', 'SW'),
    0x24: ('RAND',      'W'),
    0x25: ('VOICE',     'S'),
    0x26: ('FG2',       'S'),
}

GROUP0_SUB = {
    0x00: ('G0_TITLE',    ''),
    0x01: ('G0_MSG_INIT', ''),
    0x02: ('G0_MSG_HIDE', ''),
    0x04: ('G0_CLEAR',    ''),
    0x08: ('G0_SCREEN',   'LL'),
    0x09: ('G0_SAVE',     ''),
    0x0A: ('G0_LOAD',     ''),
    0x0B: ('G0_BGM',      'L'),
    0x0C: ('G0_BGM_STOP', 'L'),
    0x0D: ('G0_VOICE_ON', ''),
    0x0E: ('G0_VOICE_SET', 'S'),
    0x0F: ('G0_SE',       'L'),
    0x10: ('G0_SE_STOP',  'L'),
    0x14: ('G0_MENU',     ''),
    0x33: ('G0_FIN',      'L'),
    0x34: ('G0_SKIP_ON',  ''),
    0x35: ('G0_TITLE2',   ''),
    0x37: ('G0_SKIP_OFF', ''),
}


class ParseError(Exception):
    pass


# ---- 标签表 --------------------------------------------------------------

def parse_labels(data: bytes):
    """返回 (labels, bc_start, trailer).

    labels 是 [(name_bytes, offset), ...], 全是真标签 (有 u32 offset 字段)。
    bc_start = min(label offsets), 即字节码第一条指令的位置。
    trailer 是 labels 表末尾到 bc_start 之间的原始字节 (可能为空)。

    扫描规则 (5 个已验证样本上统一):
      1. 读到一条候选 (name + offset), 要求 entry_end <= bc_start_candidate
         即这条不能 "跨过" 已知的字节码起点
      2. 接受后更新 bc_start_candidate = min(..., off)
      3. 若 next_p >= bc_start_candidate 则停止 (字节码区域)
      4. trailer = data[next_p : bc_start_candidate]

    这个判据同时处理:
      - Daytalk.scr: next_p 恰好等于 bc_start, 读完自然停
      - Ay_Sp_Sn / Talk: 紧贴对齐, next_p == bc_start 时立即停
      - Sa_JJ_Wk: 有 2 字节填充 trailer, 下一条候选跨过 bc_start
      - Noone_ED: 有 39 字节 CP932 注释 trailer, 下一条候选跨过 bc_start
    """
    if data[:4] != MAGIC:
        raise ParseError(f'bad magic: {data[:4]!r}')

    labels = []
    bc_start = None
    p = 4
    while p < len(data):
        # 终止条件 A: p 已经到达/越过当前 bc_start (字节码区)
        if bc_start is not None and p >= bc_start:
            break
        end = data.find(b'\x00', p)
        if end < 0 or end == p:
            break
        if end + 5 > len(data):
            break
        name_bytes = data[p:end]
        off = struct.unpack_from('<I', data, end + 1)[0]
        entry_end = end + 1 + 4

        # 基本合法性: offset 必须指向文件内自己之后的位置
        if not (entry_end <= off < len(data)):
            break
        # 终止条件 B: 这条候选会跨过已知 bc_start → 是字节码, 不是标签
        if bc_start is not None and entry_end > bc_start:
            break

        labels.append((name_bytes, off))
        if bc_start is None or off < bc_start:
            bc_start = off
        p = entry_end

    if not labels:
        raise ParseError('no labels found')
    if p > bc_start:
        raise ParseError(
            f'label table overflow: tail={p:#x} > bc_start={bc_start:#x}')

    trailer = data[p:bc_start] if p < bc_start else b''
    return labels, bc_start, trailer


def build_label_table(labels, trailer=b''):
    """把 [(name_bytes, offset), ...] + trailer 序列化为标签表字节.

    trailer 是任意字节 (padding 或 CP932 注释), 原样拼接到标签之后。
    """
    buf = bytearray()
    for name, off in labels:
        if isinstance(name, str):
            name = name.encode('cp932')
        buf += name + b'\x00'
        buf += struct.pack('<I', off)
    if trailer:
        buf += trailer
    return bytes(buf)


# ---- 指令反汇编 ----------------------------------------------------------

def _read_args(data: bytes, p: int, fmt: str):
    vals = []
    for ch in fmt:
        if ch == 'W':
            vals.append(struct.unpack_from('<H', data, p)[0]); p += 2
        elif ch == 'L':
            vals.append(struct.unpack_from('<I', data, p)[0]); p += 4
        elif ch == 'S':
            end = data.find(b'\x00', p)
            if end < 0:
                raise ParseError(f'cstring unterminated @ {p:#x}')
            vals.append(data[p:end]); p = end + 1
        else:
            raise ParseError(f'bad fmt {ch!r}')
    return vals, p


def disasm_one(data: bytes, p: int):
    """反汇编一条指令, 返回 (insn_dict, new_pc).

    insn_dict 字段:
        pc    : 起始偏移
        kind  : 'op' / 'text'
        raw   : 完整字节 (含 opcode 和所有参数, 用于原样写回)
        -- 若 kind == 'op' --
        op    : opcode (0..0x26)
        sub   : group0 sub_op (仅 op==0 时)
        name  : 助记符
        args  : 参数列表 (整数 或 bytes)
        -- 若 kind == 'text' --
        text  : 裸 CP932 字节 (不含尾 \0)
    """
    start = p
    if p + 2 > len(data):
        raise ParseError(f'EOF mid-op @ {p:#x}')
    op = struct.unpack_from('<H', data, p)[0]

    # 未知 opcode → default 分支 → 文本模式
    # 回退到 start, 按 cstring 读一段 CP932 文本
    if op not in OUTER_OPS:
        end = data.find(b'\x00', start)
        if end < 0:
            raise ParseError(f'text cstring unterminated @ {start:#x}')
        return {
            'pc': start,
            'kind': 'text',
            'raw': data[start:end + 1],
            'text': data[start:end],
        }, end + 1

    name, fmt = OUTER_OPS[op]
    p += 2

    if op == 0x00:
        # group 0: 再读一个 u16 sub_op
        if p + 2 > len(data):
            raise ParseError(f'EOF mid-group0 @ {p:#x}')
        sub = struct.unpack_from('<H', data, p)[0]
        p += 2
        sub_name, sub_fmt = GROUP0_SUB.get(sub, (f'G0_{sub:02X}?', ''))
        vals, p = _read_args(data, p, sub_fmt)
        return {
            'pc': start, 'kind': 'op', 'op': op, 'sub': sub,
            'name': f'GROUP0.{sub_name}',
            'args': vals, 'raw': data[start:p],
        }, p

    if op == 0x04:
        # BG: cstring, 若首字符 '+' 再读 LL
        vals, p = _read_args(data, p, 'S')
        if vals[0][:1] == b'+':
            extra, p = _read_args(data, p, 'LL')
            vals += extra
        return {
            'pc': start, 'kind': 'op', 'op': op, 'name': name,
            'args': vals, 'raw': data[start:p],
        }, p

    if op in (0x12, 0x19):
        # MENU / SELECT: u16 n + n × cstring
        if p + 2 > len(data):
            raise ParseError(f'EOF mid-menu @ {p:#x}')
        n = struct.unpack_from('<H', data, p)[0]; p += 2
        items = []
        for _ in range(n):
            end = data.find(b'\x00', p)
            if end < 0:
                raise ParseError(f'menu entry unterminated @ {p:#x}')
            items.append(data[p:end]); p = end + 1
        return {
            'pc': start, 'kind': 'op', 'op': op, 'name': name,
            'args': [n] + items, 'raw': data[start:p],
        }, p

    # 通用路径
    vals, p = _read_args(data, p, fmt)
    return {
        'pc': start, 'kind': 'op', 'op': op, 'name': name,
        'args': vals, 'raw': data[start:p],
    }, p


def disasm_all(data: bytes):
    """完整反汇编, 返回 (labels, bc_start, pc_to_labels, insns, trailer)."""
    labels, bc_start, trailer = parse_labels(data)
    pc_to_labels = {}
    for name, off in labels:
        pc_to_labels.setdefault(off, []).append(name)

    insns = []
    p = bc_start
    while p < len(data):
        insn, p = disasm_one(data, p)
        insns.append(insn)
    return labels, bc_start, pc_to_labels, insns, trailer
