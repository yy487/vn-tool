#!/usr/bin/env python3
"""AI5WIN 百鬼 (Hyakki) MES codec: LZSS + script structure + (dis)assembler.

本模块只做字节级转换,不涉及文本提取/注入策略。

MES 文件整体结构:
    file_bytes = LZSS_compress(plain)
    plain      = [u32 count][u32 offsets[count]][bytecode...]
        count         — 本文件中 0x15 MESSAGE 指令的条数
                        (剧情 MES > 0, UI/init MES == 0)
        offsets[i]    — 第 i 条 message 在 bytecode 区的相对偏移 (v2 约定)
                        真实文件偏移 = 4 + count*4 + offsets[i]
        bytecode      — 线性 opcode 流,末尾无终止符

LZSS 参数: 标准 AI5 V4
    - 4 KB 环形字典, 初始写指针 0xFEE
    - 控制字节 LSB-first, bit=1 字面字节, bit=0 匹配节
    - 匹配节 2 字节 lo|hi: offset = lo | ((hi & 0xF0) << 4) [12 bit]
                          length = (hi & 0x0F) + 3         [4 bit, 3..18]
    - 最小匹配长度 3

Opcode 表 (百鬼 / Interlude 版本, silky_mes v0 基础 + 两处修正):
    0x15 MESSAGE 参数 'I'   (silky_mes v0 标为 MENU '', 错误)
    0x16 FLAG_D_SET 参数 'BC' (silky_mes 所有版本标为 'BCG', 错误)
"""
import struct
from typing import List, Tuple, Optional


# ═══════════════════════════════════════════════════════════════
#  LZSS (AI5 V4 standard)
# ═══════════════════════════════════════════════════════════════

_LZSS_WINDOW   = 0x1000   # 4 KB
_LZSS_INIT_POS = 0xFEE
_LZSS_MIN_LEN  = 3
_LZSS_MAX_LEN  = 18       # 3 + 0x0F


def lzss_decompress(data: bytes) -> bytes:
    out = bytearray()
    window = bytearray(_LZSS_WINDOW)
    wpos = _LZSS_INIT_POS
    i = 0
    ctrl = 0
    bitcnt = 0
    n = len(data)
    while i < n:
        if bitcnt == 0:
            ctrl = data[i]; i += 1; bitcnt = 8
        if ctrl & 1:
            if i >= n: break
            b = data[i]; i += 1
            out.append(b)
            window[wpos] = b; wpos = (wpos + 1) & (_LZSS_WINDOW - 1)
        else:
            if i + 1 >= n: break
            lo = data[i]; hi = data[i + 1]; i += 2
            off = lo | ((hi & 0xF0) << 4)
            ln  = (hi & 0x0F) + _LZSS_MIN_LEN
            for k in range(ln):
                b = window[(off + k) & (_LZSS_WINDOW - 1)]
                out.append(b)
                window[wpos] = b; wpos = (wpos + 1) & (_LZSS_WINDOW - 1)
        ctrl >>= 1; bitcnt -= 1
    return bytes(out)


def lzss_compress(data: bytes) -> bytes:
    """伪压缩: 全字面 flag, 不做匹配搜索.
    对 N 字节输入产生 N + ceil(N/8) 字节输出 (膨胀 ~1.14x),
    解压结果与原字节完全一致。
    """
    out = bytearray()
    n = len(data)
    i = 0
    while i < n:
        chunk = data[i:i + 8]
        flag = (1 << len(chunk)) - 1   # 每 bit 都=1 => 字面字节
        out.append(flag)
        out.extend(chunk)
        i += 8
    return bytes(out)


# ═══════════════════════════════════════════════════════════════
#  MES 头部
# ═══════════════════════════════════════════════════════════════

def parse_mes_header(plain: bytes) -> Tuple[int, List[int], int]:
    """返回 (count, first_offsets, bc_start)."""
    count = struct.unpack_from('<I', plain, 0)[0]
    offsets = [struct.unpack_from('<I', plain, 4 + i * 4)[0] for i in range(count)]
    bc_start = 4 + count * 4
    return count, offsets, bc_start


def build_mes_header(count: int, first_offsets: List[int]) -> bytes:
    assert len(first_offsets) == count
    buf = bytearray()
    buf += struct.pack('<I', count)
    for o in first_offsets:
        buf += struct.pack('<I', o)
    return bytes(buf)


# ═══════════════════════════════════════════════════════════════
#  Opcode / struct 表
# ═══════════════════════════════════════════════════════════════

# (arg_fmt, name). name 可为 '' / 'op_XX',仅供显示.
OPCODES = {
    0x00: ('',     'RETURN'),
    0x01: ('S',    'TEXT'),
    0x02: ('C',    'op_02'),
    0x03: ('BCG',  'B_FLAG_SET'),
    0x04: ('BCG',  'W_FLAG_SET'),
    0x05: ('CCG',  'EXT_B_FLAG_SET'),
    0x06: ('CBCG', 'PC_FLAG_SET'),
    0x07: ('CBCG', 'A_FLAG_SET'),
    0x08: ('CBCG', 'op_08'),
    0x09: ('CI',   'JUMP_IF'),
    0x0a: ('I',    'JUMP'),
    0x0b: ('C',    'op_0b'),
    0x0c: ('',     'op_0c'),
    0x0d: ('',     'op_0d'),
    0x0e: ('CGI',  'LABEL'),
    0x0f: ('CG',   'CALL'),
    0x10: ('',     'op_10'),
    0x11: ('V',    'INTERRUPT'),
    0x12: ('CI',   'INTERRUPT_IF'),
    0x13: ('',     'op_13'),
    0x14: ('CG',   'op_14'),
    0x15: ('I',    'MESSAGE'),     # << 百鬼: 带 u32 参数
    0x16: ('BC',   'FLAG_D_SET'),  # << 百鬼: 不是 BCG
    0x51: ('H',    'op_51'),
}

# C 结构体的子字节表: struct_byte -> 其子参数格式
STRUCT_LIB = {
    0x80: 'B', 0xA0: 'B', 0xC0: 'B',
    0xE0: '', 0xE1: '', 0xE2: '', 0xE3: '', 0xE4: '', 0xE5: '',
    0xE6: '', 0xE7: '', 0xE8: '', 0xE9: '', 0xEA: '',
    0xEB: '', 0xEC: '', 0xED: '', 0xEE: '', 0xEF: '',
    0xF0: '',
    0xF1: 'h', 0xF2: 'i', 0xF3: 'H',
    0xF4: '',
    0xF5: 'B', 0xF6: 'B', 0xF7: 'B', 0xF8: 'B',
    0xFF: '',   # STRUCT_END
}

# opcode -> 其 I 参数中"是跳转目标"的那一个 I 的序号 (第几个 I, 从 0 起)
JUMP_I_INDEX = {
    0x09: 1,   # JUMP_IF      CI -> C, I(target)
    0x0a: 0,   # JUMP         I(target)
    0x0e: 2,   # LABEL        CGI -> C, G, I(target)
    0x12: 1,   # INTERRUPT_IF CI -> C, I(target)
}


# ═══════════════════════════════════════════════════════════════
#  反汇编: 把 bytecode 流拆成指令序列
# ═══════════════════════════════════════════════════════════════

class Instr:
    """单条指令 (反汇编结果 / 汇编输入).

    `raw` 是此条指令在原始 bytecode 中完整字节的拷贝 (含 opcode 本身).
    如此设计可以让非文本/非跳转指令在 assemble 时零成本原样写回,
    也让变长注入只需 patch 少量字段即可, 最大化鲁棒性.
    """
    __slots__ = ('op', 'raw', 'old_pos', 'new_pos')

    def __init__(self, op: int, raw: bytes, old_pos: int):
        self.op = op
        self.raw = bytes(raw)
        self.old_pos = old_pos   # bc-相对原始位置
        self.new_pos = old_pos   # bc-相对新位置 (assemble 时填)

    def __repr__(self):
        return f"Instr(op={self.op:02x} len={len(self.raw)} old={self.old_pos:x})"


class DisasmError(Exception):
    pass


def _skip_args(buf: bytes, pos: int, fmt: str) -> int:
    """按 fmt 向前推 pos, 不捕获任何值, 只返回新 pos."""
    i = 0
    n = len(fmt)
    while i < n:
        c = fmt[i]; i += 1
        if   c == 'I': pos += 4
        elif c == 'H': pos += 2
        elif c == 'B': pos += 1
        elif c == 'h': pos += 2
        elif c == 'i': pos += 4
        elif c == 'S':
            while buf[pos] != 0: pos += 1
            pos += 1
        elif c == '6':
            while buf[pos] != 0x06: pos += 1
            pos += 1
        elif c == 'C':
            while True:
                sb = buf[pos]; pos += 1
                sa = STRUCT_LIB.get(sb)
                if sa is None:
                    continue   # RAW byte, no extra consume
                if sa:
                    pos = _skip_args(buf, pos, sa)
                if sb == 0xFF:
                    break
        elif c == 'V':
            while True:
                d = buf[pos]; pos += 1
                if d == 0: break
                elif d == 1: pos = _skip_args(buf, pos, 'S')
                elif d == 2: pos = _skip_args(buf, pos, 'C')
                else:
                    raise DisasmError(f"bad V definer {d} at {pos - 1:x}")
        elif c == 'G':
            while True:
                cf = buf[pos]; pos += 1
                if cf == 0: break
                pos = _skip_args(buf, pos, 'C')
        else:
            raise DisasmError(f"unknown fmt char {c!r}")
    return pos


def disassemble(bc: bytes) -> List[Instr]:
    """把 bytecode 区 (绝对于 bc_start 的纯指令流) 拆成 Instr 列表.

    未知 opcode 按 silky_mes 规则视为 free byte (单字节推进).
    """
    instrs: List[Instr] = []
    pos = 0
    end = len(bc)
    while pos < end:
        op = bc[pos]
        p0 = pos
        pos += 1
        entry = OPCODES.get(op)
        if entry is None:
            # 未知字节 -> 单字节占位 instr
            instrs.append(Instr(op, bc[p0:pos], p0))
            continue
        fmt, _name = entry
        try:
            pos = _skip_args(bc, pos, fmt)
        except (IndexError, DisasmError) as e:
            raise DisasmError(
                f"parse failure at bc offset 0x{p0:x} op={op:02x}: {e}"
            ) from e
        instrs.append(Instr(op, bc[p0:pos], p0))
    return instrs


# ═══════════════════════════════════════════════════════════════
#  Instr 辅助: 读 MESSAGE id / 读写 JUMP 目标 / 改 TEXT 字符串
# ═══════════════════════════════════════════════════════════════

def get_message_id(instr: Instr) -> int:
    assert instr.op == 0x15
    return struct.unpack_from('<I', instr.raw, 1)[0]


def set_message_id(instr: Instr, new_id: int) -> None:
    assert instr.op == 0x15
    buf = bytearray(instr.raw)
    struct.pack_into('<I', buf, 1, new_id)
    instr.raw = bytes(buf)


def _find_ith_I_offset_in_fmt(fmt: str) -> Optional[int]:
    """返回第 JUMP_I_INDEX[op] 个 I 在 raw 中相对 opcode 字节之后的起始偏移.

    因为 C/V/G/S 是变长, 这里要真解析一遍.
    返回 None 表示该 opcode 没有跳转 I.
    """
    # not used directly; we parse on demand via parse_with_offsets
    pass


def get_jump_target(instr: Instr) -> Optional[int]:
    """若此指令含跳转目标 I, 返回其值; 否则返回 None."""
    if instr.op not in JUMP_I_INDEX:
        return None
    target_idx = JUMP_I_INDEX[instr.op]
    fmt = OPCODES[instr.op][0]
    # 扫描 fmt, 计算第 target_idx 个 'I' 的位置
    pos = 1   # 跳过 opcode 字节
    i_seen = 0
    k = 0
    while k < len(fmt):
        c = fmt[k]; k += 1
        if c == 'I':
            if i_seen == target_idx:
                return struct.unpack_from('<I', instr.raw, pos)[0]
            i_seen += 1
            pos += 4
        elif c == 'H': pos += 2
        elif c == 'B': pos += 1
        elif c == 'h': pos += 2
        elif c == 'i': pos += 4
        elif c == 'S':
            while instr.raw[pos] != 0: pos += 1
            pos += 1
        elif c == '6':
            while instr.raw[pos] != 0x06: pos += 1
            pos += 1
        elif c == 'C':
            pos = _skip_args(instr.raw, pos, 'C')
        elif c == 'V':
            pos = _skip_args(instr.raw, pos, 'V')
        elif c == 'G':
            pos = _skip_args(instr.raw, pos, 'G')
    return None


def set_jump_target(instr: Instr, new_target: int) -> None:
    """就地改写此指令的跳转目标 I."""
    if instr.op not in JUMP_I_INDEX:
        raise ValueError(f"op {instr.op:02x} has no jump target")
    target_idx = JUMP_I_INDEX[instr.op]
    fmt = OPCODES[instr.op][0]
    pos = 1
    i_seen = 0
    k = 0
    while k < len(fmt):
        c = fmt[k]; k += 1
        if c == 'I':
            if i_seen == target_idx:
                buf = bytearray(instr.raw)
                struct.pack_into('<I', buf, pos, new_target)
                instr.raw = bytes(buf)
                return
            i_seen += 1
            pos += 4
        elif c == 'H': pos += 2
        elif c == 'B': pos += 1
        elif c == 'h': pos += 2
        elif c == 'i': pos += 4
        elif c == 'S':
            while instr.raw[pos] != 0: pos += 1
            pos += 1
        elif c == '6':
            while instr.raw[pos] != 0x06: pos += 1
            pos += 1
        elif c == 'C': pos = _skip_args(instr.raw, pos, 'C')
        elif c == 'V': pos = _skip_args(instr.raw, pos, 'V')
        elif c == 'G': pos = _skip_args(instr.raw, pos, 'G')
    raise RuntimeError("unreachable")


def get_text_string(instr: Instr) -> bytes:
    """若此指令是 0x01 TEXT, 返回其 null 终止前的原始字节 (不含 \\x00)."""
    assert instr.op == 0x01
    return instr.raw[1:-1]   # skip opcode, strip trailing NUL


def set_text_string(instr: Instr, new_bytes: bytes) -> None:
    """就地改写 TEXT 指令的字符串 (bytes 不应含 \\x00)."""
    assert instr.op == 0x01
    assert b'\x00' not in new_bytes, "TEXT payload must not contain NUL"
    instr.raw = bytes([0x01]) + bytes(new_bytes) + b'\x00'


# ═══════════════════════════════════════════════════════════════
#  重汇编: Instr 列表 -> bytecode + 新 first_offsets
# ═══════════════════════════════════════════════════════════════

def assemble(instrs: List[Instr], original_first_offsets: List[int]) -> Tuple[bytes, List[int]]:
    """把 Instr 列表重新线性化为 bytecode, 同时修复所有跳转和 first_offsets.

    Two-pass:
        pass 1: 按当前 raw 长度计算每条 instr 的 new_pos (bc-相对)
        pass 2: 对含跳转的 instr, 把 target (旧 bc-相对) 转成 new bc-相对
                然后重写 raw; 再来一次 pass 1 刷新 new_pos (因为 raw 没变长这里)
                实际上 JUMP I 长度固定 4B, 改写不会影响布局, 所以一次够.

    同时返回新的 first_offsets 列表 (长度 == 原 count).
    """
    # 构建旧位置 -> Instr 的映射 (按 old_pos)
    old_to_instr = {ins.old_pos: ins for ins in instrs}

    # pass 1: 线性布置 new_pos
    p = 0
    for ins in instrs:
        ins.new_pos = p
        p += len(ins.raw)

    # pass 2: 修复跳转
    for ins in instrs:
        if ins.op in JUMP_I_INDEX:
            old_target = get_jump_target(ins)
            if old_target is None:
                continue
            tgt_instr = old_to_instr.get(old_target)
            if tgt_instr is None:
                raise RuntimeError(
                    f"jump at old bc 0x{ins.old_pos:x} op={ins.op:02x} "
                    f"-> target 0x{old_target:x} has no matching instr"
                )
            set_jump_target(ins, tgt_instr.new_pos)

    # 组装 bytecode
    out = bytearray()
    for ins in instrs:
        out += ins.raw

    # 修复 first_offsets
    new_first = []
    for old_fo in original_first_offsets:
        tgt = old_to_instr.get(old_fo)
        if tgt is None:
            raise RuntimeError(f"first_offset 0x{old_fo:x} has no matching instr")
        new_first.append(tgt.new_pos)

    return bytes(out), new_first


# ═══════════════════════════════════════════════════════════════
#  顶层: 完整文件编/解
# ═══════════════════════════════════════════════════════════════

def load_mes(file_bytes: bytes) -> Tuple[int, List[int], List[Instr]]:
    """读一个 .MES 文件, 返回 (count, first_offsets, instrs)."""
    plain = lzss_decompress(file_bytes)
    count, first_offsets, bc_start = parse_mes_header(plain)
    bc = plain[bc_start:]
    instrs = disassemble(bc)
    return count, first_offsets, instrs


def save_mes(count: int,
             first_offsets: List[int],
             instrs: List[Instr],
             orig_first_offsets_for_fixup: Optional[List[int]] = None) -> bytes:
    """把 (count, first_offsets, instrs) 重汇编并 LZSS 压缩.

    若 orig_first_offsets_for_fixup 给出, 会按其值 (旧 bc-相对) 从 instrs 里
    找到对应 new_pos, 重新生成 first_offsets; 否则假定 first_offsets 已经是
    新 bc-相对的.

    用法:
      # 不改 instrs 的情况 (纯 round-trip):
      new_bc, new_fo = assemble(instrs, first_offsets)
      file = save_mes(count, new_fo, instrs_no_wrap=True)   # already assembled
    """
    raise NotImplementedError("use pack_mes() instead")


def pack_mes(count: int, new_bc: bytes, new_first_offsets: List[int]) -> bytes:
    """拼 header + bc, 然后 LZSS 压缩."""
    assert len(new_first_offsets) == count
    header = build_mes_header(count, new_first_offsets)
    plain = header + new_bc
    return lzss_compress(plain)
