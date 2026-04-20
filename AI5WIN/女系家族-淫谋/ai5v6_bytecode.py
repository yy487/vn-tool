#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI5WIN V6 MES bytecode 反汇编 / 重汇编
=====================================

v2 opcode 表 (源自 tinke/AI5WINScript 参考实现):
  支持所有已知指令的参数长度计算
  核心功能:
    - disassemble(bytecode) -> [Instruction, ...]
    - assemble([Instruction, ...]) -> bytes
    - 变长 TEXT 替换 + 所有跳转目标自动 fixup

参数格式符号 (参考 AI5WINScript):
  ''  空
  'S' null 终止字符串
  'I' u32 LE
  'H' u16 LE
  'B' u8
  'C' code structure (内嵌 opcode 流, 以 0xFF STRUCT_END 结束)
  'V' variable structure (0x00 结束)
  'G' group structure (0x00 结束)
  'F' flag ("continue if 0", 非零则 backtrack 并终止当前参数序列)
  'h' signed int16, 'i' signed int32  (struct_library 内部用, 无符号差异不影响长度)

跳转参数 (offsets_library[2]): 这些 'I' 参数指向 bytecode 内的相对偏移,
重建 bytecode 时必须整体重映射.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import struct


# ---------------------------------------------------------------------------
# v2 opcode 表
# ---------------------------------------------------------------------------

V2_OPCODES = {
    0x00: ('',     'RETURN'),
    0x01: ('S',    'TEXT'),
    0x02: ('S',    'SYSTEM_TEXT'),
    0x03: ('HCG',  'B_FLAG_SET'),
    0x04: ('BCG',  'W_FLAG_SET'),
    0x05: ('CCG',  'EXT_B_FLAG_SET'),
    0x06: ('CBCG', 'PC_FLAG_SET'),
    0x07: ('CBCG', 'A_FLAG_SET'),
    0x08: ('CFCG', 'G_FLAG_SET'),
    0x09: ('CBCG', 'PW_FLAG_SET'),
    0x0a: ('CBCG', 'PB_FLAG_SET'),
    0x0b: ('CI',   'JUMP_IF'),
    0x0c: ('I',    'JUMP'),
    0x0d: ('CV',   'SYS'),
    0x0e: ('V',    'CH_POS'),
    0x0f: ('V',    'CALL'),
    0x10: ('VI',   'MENU_SET'),
    0x11: ('V',    'INTERRUPT'),
    0x12: ('V',    'SPEC_SYS'),
    0x13: ('B',    'NEW_LINE'),
    0x14: ('CI',   'INTERRUPT_IF'),
    0x15: ('CG',   'MENU'),
    0x16: ('BCG',  'FLAG_D_SET'),
    0x17: ('I',    'MESSAGE'),      # I 参数是 MESSAGE 索引, 不是跳转
    0x18: ('',     ''),
    0x1b: ('CG',   ''),
    0x1c: ('CI',   ''),
    0x1d: ('CG',   ''),
    0x1f: ('I',    'LABEL'),
}

# 跳转参数索引 (源自 offsets_library[2])
# opcode -> 参数表中第几个 'I' 参数是跳转目标
JUMP_TARGET_ARG = {
    0x0b: 1,   # JUMP_IF:     C, I(target)
    0x0c: 0,   # JUMP:        I(target)
    0x10: 1,   # MENU_SET:    V, I(target)
    0x14: 1,   # INTERRUPT_IF: C, I(target)
    0x1c: 1,   # unknown:     C, I(target)
}

# Struct library (C 结构内部 opcode 参数长度)
# 未列出的 opcode 在参考代码里会作为 RAW byte 单字节处理
V2_STRUCT_ARGS = {
    0x80: 'B',  0xA0: 'B',  0xC0: 'B',
    0xE0: '',   0xE1: '',   0xE2: '',   0xE3: '',   0xE4: '',
    0xE5: '',   0xE6: '',   0xE7: '',   0xE8: '',   0xE9: '',
    0xEA: '',   0xEB: '',   0xEC: '',   0xED: '',   0xEE: '',
    0xEF: '',   0xF0: '',
    0xF1: 'h',  0xF2: 'i',  0xF3: 'H',
    0xF4: '',   0xF5: 'B',  0xF6: 'B',  0xF7: 'B',  0xF8: 'B',
    0xFF: '',   # STRUCT_END
}


# ---------------------------------------------------------------------------
# Instruction 表示
# ---------------------------------------------------------------------------

@dataclass
class Instruction:
    offset: int          # 在 bytecode 中的偏移 (原位置, 反汇编时记录)
    opcode: int          # 指令 opcode
    raw: bytes           # 整条指令的原始字节 (含 opcode + 所有参数)
    # 以下字段仅为 TEXT/SYSTEM_TEXT/跳转指令提供可编辑视图
    text: Optional[str] = None          # 仅 0x01/0x02: 字符串内容 (cp932 已解码)
    jump_target: Optional[int] = None   # 仅含跳转的指令: 跳转目标 (旧 bytecode 偏移)
    # 未知 opcode 的 "free byte" (长度为 1, opcode 本身即 raw)
    is_free_byte: bool = False


@dataclass
class FreeByte:
    """参考代码里遇到未知 opcode 时, 把这个字节当作 'free byte' 原样保留."""
    offset: int
    byte: int


# ---------------------------------------------------------------------------
# 参数长度计算 (不解析内容, 只算字节长度)
# ---------------------------------------------------------------------------

class _Reader:
    """字节流游标, 只负责推进, 不拷贝."""
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos
        self.start = pos

    def u8(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def peek(self) -> int:
        return self.data[self.pos]

    def skip(self, n: int):
        self.pos += n

    def slice_from_start(self) -> bytes:
        return bytes(self.data[self.start : self.pos])

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


def _skip_args(reader: _Reader, arg_fmt: str):
    """按参数格式串推进 reader, 不返回内容, 只计算边界.
    
    'S' null 终止字符串
    'I'/'i' u32
    'H'/'h' u16
    'B' u8
    'C' code struct (至 STRUCT_END=0xFF)
    'V' variable (至 0x00)
    'G' group (至 0x00)
    'F' continue-if-0: 读 1 byte, 非零则 backtrack -1 并停止后续参数
    """
    i = 0
    while i < len(arg_fmt):
        c = arg_fmt[i]
        i += 1
        if c == 'S':
            while not reader.at_end() and reader.u8() != 0:
                pass
        elif c in ('I', 'i'):
            reader.skip(4)
        elif c in ('H', 'h'):
            reader.skip(2)
        elif c == 'B':
            reader.skip(1)
        elif c == 'C':
            _skip_C(reader)
        elif c == 'V':
            _skip_V(reader)
        elif c == 'G':
            _skip_G(reader)
        elif c == 'F':
            b = reader.u8()
            if b != 0:
                # backtrack and stop consuming more args for this instruction
                reader.pos -= 1
                break
        else:
            raise ValueError(f"Unknown arg format char: {c!r}")


def _skip_C(reader: _Reader):
    """跳过 C 结构: 循环读 struct_opcode, 每个 opcode 跳过其参数, 遇 0xFF 停止."""
    while not reader.at_end():
        sop = reader.u8()
        if sop in V2_STRUCT_ARGS:
            _skip_args(reader, V2_STRUCT_ARGS[sop])
            if sop == 0xFF:
                return
        # 未知 struct opcode: 参考代码作 "RAW" 单字节, 不消耗参数, 继续循环
        # (就是 u8 已经读掉的那个字节本身)


def _skip_V(reader: _Reader):
    """跳过 V 结构: 循环读定义符, 直到 0x00."""
    while not reader.at_end():
        definer = reader.u8()
        if definer == 0:
            return
        elif definer == 1:
            # NAME: followed by 'S'
            while not reader.at_end() and reader.u8() != 0:
                pass
        elif definer == 2:
            # EXPRESSION: followed by 'C'
            _skip_C(reader)
        else:
            # 未知定义符: 保守起见视为结束
            reader.pos -= 1
            return


def _skip_G(reader: _Reader):
    """跳过 G 结构: 循环读 continue_flag, 非零后跟 'C', 零则结束."""
    while not reader.at_end():
        flag = reader.u8()
        if flag == 0:
            return
        _skip_C(reader)


# ---------------------------------------------------------------------------
# 反汇编
# ---------------------------------------------------------------------------

def disassemble(bytecode: bytes) -> List[Instruction]:
    """反汇编整段 bytecode 为 Instruction 列表.
    
    遇到未知 opcode 时, 按参考代码行为作为 'free byte' 单字节处理
    (记为 is_free_byte=True 的 Instruction).
    """
    instrs: List[Instruction] = []
    pos = 0
    n = len(bytecode)

    while pos < n:
        op = bytecode[pos]
        if op not in V2_OPCODES:
            # Free byte
            instrs.append(Instruction(
                offset=pos,
                opcode=op,
                raw=bytes([op]),
                is_free_byte=True,
            ))
            pos += 1
            continue

        arg_fmt, _name = V2_OPCODES[op]
        # 解析参数, 只为计算长度
        reader = _Reader(bytecode, pos + 1)
        try:
            _skip_args(reader, arg_fmt)
        except IndexError:
            # Bytecode 末尾截断, 把剩下当 free bytes
            instrs.append(Instruction(
                offset=pos, opcode=op, raw=bytes([op]), is_free_byte=True))
            pos += 1
            continue

        end = reader.pos
        raw = bytes(bytecode[pos:end])

        inst = Instruction(offset=pos, opcode=op, raw=raw)

        # 特殊字段提取
        if op in (0x01, 0x02):
            # TEXT/SYSTEM_TEXT: raw = [op] + string + [\0]
            try:
                inst.text = raw[1:-1].decode('cp932')
            except UnicodeDecodeError:
                inst.text = None  # 保留 raw 不改

        if op in JUMP_TARGET_ARG:
            # 找到跳转目标参数在 raw 里的偏移
            target_arg_idx = JUMP_TARGET_ARG[op]
            jt_offset = _locate_I_arg_offset(raw, arg_fmt, target_arg_idx)
            if jt_offset is not None:
                inst.jump_target = struct.unpack_from('<I', raw, jt_offset)[0]

        instrs.append(inst)
        pos = end

    return instrs


def _locate_I_arg_offset(raw: bytes, arg_fmt: str, target_arg_pos: int) -> Optional[int]:
    """在 raw 指令中定位第 target_arg_pos 个参数 (按 arg_fmt 字符位置 0-indexed) 的字节偏移.
    
    target_arg_pos 对应 arg_fmt 字符串里的索引, 跳过 technical instances 之后.
    例如 arg_fmt='CI', target_arg_pos=1 定位 I 参数 (C 之后).
    """
    reader = _Reader(raw, 1)  # 跳过 opcode
    i = 0
    current_arg_pos = 0
    while i < len(arg_fmt):
        c = arg_fmt[i]
        i += 1
        if current_arg_pos == target_arg_pos:
            return reader.pos
        current_arg_pos += 1
        if c == 'S':
            while reader.u8() != 0:
                pass
        elif c in ('I', 'i'):
            reader.skip(4)
        elif c in ('H', 'h'):
            reader.skip(2)
        elif c == 'B':
            reader.skip(1)
        elif c == 'C':
            _skip_C(reader)
        elif c == 'V':
            _skip_V(reader)
        elif c == 'G':
            _skip_G(reader)
        elif c == 'F':
            b = reader.u8()
            if b != 0:
                reader.pos -= 1
                break
    return None


# ---------------------------------------------------------------------------
# 指令序列化 (把 Instruction 重新输出为 bytes)
# ---------------------------------------------------------------------------

def _rewrite_text_instruction(inst: Instruction, new_text: str) -> bytes:
    """对 0x01/0x02 指令重建 raw bytes, 带新字符串."""
    encoded = new_text.encode('cp932')
    return bytes([inst.opcode]) + encoded + b'\x00'


def _rewrite_jump_target(raw: bytes, arg_fmt: str, target_idx: int, new_target: int) -> bytes:
    """修改 raw 指令里第 target_idx 个 I 参数的值."""
    jt_off = _locate_I_arg_offset(raw, arg_fmt, target_idx)
    if jt_off is None:
        return raw
    out = bytearray(raw)
    struct.pack_into('<I', out, jt_off, new_target)
    return bytes(out)


def assemble(instrs: List[Instruction]) -> tuple:
    """把 Instruction 列表重新组装为 bytecode, 自动修正所有跳转目标.
    
    工作流程:
    1. 第一遍: 根据 (可能已改过的) raw 算出每条指令的新 offset,
       建立 old_offset -> new_offset 映射.
    2. 第二遍: 对含跳转目标的指令, 用映射表更新 raw 里的 I 参数.
    3. 第三遍: 拼接所有 raw.
    
    返回 (bytecode, offset_map), offset_map 供外部 first_offsets 映射使用.
    """
    # 第一遍: 计算新偏移
    old_to_new = {}
    new_pos = 0
    for inst in instrs:
        old_to_new[inst.offset] = new_pos
        new_pos += len(inst.raw)

    # 第二遍: fix jump targets
    for inst in instrs:
        if inst.is_free_byte or inst.opcode not in JUMP_TARGET_ARG:
            continue
        old_target = inst.jump_target
        if old_target is None:
            continue
        if old_target not in old_to_new:
            # 跳转目标不在指令边界上 — 罕见, 保守起见保持原值
            # 这通常意味着之前反汇编有偏差, 或目标在 free_byte 区域
            continue
        new_target = old_to_new[old_target]
        if new_target != old_target:
            arg_fmt, _ = V2_OPCODES[inst.opcode]
            target_idx = JUMP_TARGET_ARG[inst.opcode]
            inst.raw = _rewrite_jump_target(inst.raw, arg_fmt, target_idx, new_target)
            inst.jump_target = new_target

    # 第三遍: 拼接
    out = bytearray()
    for inst in instrs:
        out.extend(inst.raw)

    return bytes(out), old_to_new
