#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai5v7_bytecode_v2.py — V7 (Silky's 2001 "愛しの言霊") MES 字节码反汇编 + 重汇编

与 v1 的关键修正:
  1. **MES 是 LZSS 压缩的** (旧版记忆里的"无压缩"是错的)
     - 标准 AI5 LZSS: 4KB 环形窗口 init=0xFEE, LSB-first flag, 12b off + 4b len
     - 解压函数 FUN_00414060 (ARC 路径才做,散文件 FUN_00417760 不做)
  2. **C 表达式求值器 (FUN_0040ec50) 的 opcode 表重做**:
     - 0xa0/0xc0/0xf4/0xf5 从栈 pop,**不嵌套 C 表达式**
     - 0xf7/0xf8 根本没有 case,是字面量
     - 0xf1 2字节立即数, 0xf2 4字节立即数, 0xf3 2字节 idx, 0xf6 1字节 idx
  3. 主 opcode 的 V 结构其实只消费字节流 tag 0/1/2,tag=0 结束
"""
import struct


# ---------------------------------------------------------------------------
# LZSS 解压 / 压缩 (与 FUN_00414060 对齐)
# ---------------------------------------------------------------------------
def lzss_decompress(src):
    """AI5 标准 LZSS: 4KB 环形窗口 init=0xFEE, LSB-first flag,
       bit=1: literal byte
       bit=0: 12-bit offset + 4-bit length code, len = code+3
       终止条件: src EOF (不像某些变种用显式 size)"""
    WIN_SIZE = 0x1000
    window = bytearray(WIN_SIZE)
    wpos = 0xFEE
    out = bytearray()
    sp = 0
    flag_word = 0   # 使用 (x | 0xFF00) 位耗尽检测

    while sp < len(src):
        flag_word >>= 1
        if (flag_word & 0x100) == 0:
            if sp >= len(src):
                break
            flag_word = src[sp] | 0xFF00
            sp += 1
        if flag_word & 1:
            if sp >= len(src):
                break
            b = src[sp]; sp += 1
            out.append(b)
            window[wpos] = b
            wpos = (wpos + 1) & 0xFFF
        else:
            if sp + 1 >= len(src):
                break
            b1 = src[sp]; sp += 1
            b2 = src[sp]; sp += 1
            mlen = (b2 & 0x0F) + 3
            mpos = (b1 | ((b2 & 0xF0) << 4)) & 0xFFF
            for i in range(mlen):
                b = window[(mpos + i) & 0xFFF]
                out.append(b)
                window[wpos] = b
                wpos = (wpos + 1) & 0xFFF
    return bytes(out)


def lzss_compress_fake(plain):
    """伪 LZSS 压缩: 每 8 字节一个 0xFF flag + 8 个字面量.
       不做匹配搜索, 解压结果与原文字节级一致, 膨胀 ~1.125x."""
    out = bytearray()
    i = 0
    while i < len(plain):
        chunk = plain[i : i + 8]
        out.append(0xFF)           # 8 个 literal bit
        out += chunk
        i += 8
    return bytes(out)


# ---------------------------------------------------------------------------
# C 表达式求值器 (FUN_0040ec50) 的 opcode 定义
# ---------------------------------------------------------------------------
# 格式 (byte_fmt, stack_pops_before)
#   byte_fmt: 额外字节的读取格式, 字符含义:
#     'B'=u8, 'H'=u16, 'I'=u32
#   stack_pops_before: opcode 执行时从求值栈 pop 的数量 (仅用于记录, 反汇编时不需要模拟栈)
#
# 验证依据: Ghidra FUN_0040ec50 line 24035-24195
C_STRUCT_OPS = {
    # name, extra_byte_fmt
    0x80: ('W_FLAG',    'B'),    # read u8 idx, 访问 this+0x884+idx*2 的 u16
    0xA0: ('A_FLAG',    'B'),    # pop idx, read u8 bank, 访问 this+0x880 或跳转表
    0xC0: ('PC_FLAG',   'B'),    # pop idx, read u8 bank, 访问 this+0x884+bank*2 字节表

    0xE0: ('ADD',       ''),
    0xE1: ('SUB',       ''),
    0xE2: ('MUL',       ''),
    0xE3: ('DIV',       ''),
    0xE4: ('REM',       ''),
    0xE5: ('RND',       ''),
    0xE6: ('BAND',      ''),
    0xE7: ('BOR',       ''),
    0xE8: ('AND',       ''),
    0xE9: ('OR',        ''),
    0xEA: ('XOR',       ''),
    0xEB: ('LT',        ''),
    0xEC: ('GT',        ''),
    0xED: ('LE',        ''),
    0xEE: ('GE',        ''),
    0xEF: ('EQ',        ''),
    0xF0: ('NE',        ''),

    0xF1: ('IMM16',     'H'),    # 2 字节立即数 (push)
    0xF2: ('IMM32',     'I'),    # 4 字节立即数 (push)
    0xF3: ('EXT_B_FLAG','H'),    # 2 字节 idx, 访问 this+0x80+idx 字节
    0xF4: ('B_FLAG',    ''),     # pop idx, 访问 this+0x80+idx 字节 (无字节参数!)
    0xF5: ('G_FLAG',    'B'),    # pop idx, read u8 bank
    0xF6: ('PW_FLAG',   'B'),    # read u8 idx, 访问 this+0x8e8+idx*4 u32
    # 0xF7/0xF8 没有 case, 走 default = 字面量 push
}

# 0xFF 是终止符, 不在表里 (特殊处理)

OP_NAME_TO_BYTE = {name: op for op, (name, _) in C_STRUCT_OPS.items()}


# ---------------------------------------------------------------------------
# 主 opcode 表 (21 条, 0x00-0x14)
# 依据 FUN_00404110 line 17986-18120
# ---------------------------------------------------------------------------
OPCODES = {
    0x00: ('RETURN',        ''),
    0x01: ('TEXT',          'S'),     # SJIS 隐式后退路径其实也到这里? 待验证
    0x02: ('TEXT_SYS',      'S'),     # 半角文本路径
    0x03: ('B_FLAG_SET',    'HG'),
    0x04: ('W_FLAG_SET',    'BG'),
    0x05: ('EXT_B_FLAG_SET','CG'),
    0x06: ('PC_FLAG_SET',   'CBG'),
    0x07: ('A_FLAG_SET',    'CBG'),
    0x08: ('D_FLAG_SET',    'CBG'),
    0x09: ('JUMP_IF',       'CI'),
    0x0A: ('JUMP',          'I'),
    0x0B: ('SYS',           'CV'),
    0x0C: ('LOAD',          'V'),
    0x0D: ('CALL',          'V'),
    0x0E: ('MENU_INIT',     'CVH'),
    0x0F: ('CH_POS',        'C'),
    0x10: ('SYS_RAW',       ''),      # vtable+0x2c 虚函数, 无参
    0x11: ('NEW_LINE',      'B'),
    0x12: ('INTERRUPT_IF',  'CI'),
    0x13: ('MENU_SHOW',     ''),
    0x14: ('DW_FLAG_SET',   'BG'),
}

NAME_TO_OPCODE = {name: op for op, (name, _) in OPCODES.items()}


def is_sjis_lead(b):
    """FUN_00404110 的 SJIS 判定 (default case)"""
    return (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xEF) or (0xFA <= b <= 0xFC)


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------
class Reader:
    __slots__ = ('data', 'pos')
    def __init__(self, data, pos=0):
        self.data = data
        self.pos  = pos
    def peek(self):
        return self.data[self.pos]
    def u8(self):
        b = self.data[self.pos]; self.pos += 1; return b
    def u16(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]; self.pos += 2; return v
    def u32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v
    def eof(self):
        return self.pos >= len(self.data)


# ---------------------------------------------------------------------------
# C / V / G / S 读写
# ---------------------------------------------------------------------------
def read_C(r):
    """C 表达式, 0xFF 终止. item 形如:
       ('END',) / ('LIT', b) / (op_name, [args...])"""
    items = []
    while True:
        if r.eof():
            raise ValueError(f'C: EOF at 0x{r.pos:x}')
        b = r.u8()
        if b == 0xFF:
            items.append(('END',))
            return items
        if b in C_STRUCT_OPS:
            name, extra = C_STRUCT_OPS[b]
            args = []
            for c in extra:
                if c == 'B':   args.append(r.u8())
                elif c == 'H': args.append(r.u16())
                elif c == 'I': args.append(r.u32())
            items.append((name, args))
        else:
            # 所有未被占用的字节 = 字面量 push (包括 0xf7/0xf8/0xf9-0xfe)
            items.append(('LIT', b))


def write_C(items, buf):
    for item in items:
        tag = item[0]
        if tag == 'END':
            buf.append(0xFF)
        elif tag == 'LIT':
            buf.append(item[1])
        else:
            op = OP_NAME_TO_BYTE.get(tag)
            if op is None:
                raise ValueError(f'unknown C op name {tag!r}')
            buf.append(op)
            extra = C_STRUCT_OPS[op][1]
            args = item[1]
            ai = 0
            for c in extra:
                v = args[ai]; ai += 1
                if c == 'B':   buf.append(v)
                elif c == 'H': buf += struct.pack('<H', v)
                elif c == 'I': buf += struct.pack('<I', v)


def read_V(r):
    """V 结构 (FUN_004038d0):
       while peek() != 0:
           tag = consume()
           if tag == 1: 读 0 终止字符串
           elif tag == 2: 读 C 表达式 (ec50 消费到 0xff)
           else: **什么都不做** (源码里 if/else-if 没有 else 分支)
                 反汇编器把它当作不透明的 1 字节 OPAQUE 槽位保留原字节
       consume()  # 吃掉末尾的 0
       items: [('STR', bytes) | ('EXPR', c_items) | ('OPAQUE', int)]"""
    items = []
    while True:
        if r.eof():
            raise ValueError(f'V: EOF at 0x{r.pos:x}')
        if r.peek() == 0:
            r.u8()  # 吃掉 V 终止符 0
            return items
        tag = r.u8()
        if tag == 1:
            s_start = r.pos
            while True:
                if r.eof():
                    raise ValueError(f'V STR: EOF at 0x{r.pos:x}')
                if r.u8() == 0:
                    break
            items.append(('STR', bytes(r.data[s_start : r.pos - 1])))
        elif tag == 2:
            items.append(('EXPR', read_C(r)))
        else:
            # 源码 FUN_004038d0 在 if/else-if 后没有 else, 即 tag != 1/2 时
            # 外层循环什么都不做直接继续 — 意味着这 1 字节被消费但无语义
            # 保留为 OPAQUE 以便重汇编时字节级还原
            items.append(('OPAQUE', tag))


def write_V(items, buf):
    for tag, val in items:
        if tag == 'STR':
            buf.append(1)
            buf += val
            buf.append(0)
        elif tag == 'EXPR':
            buf.append(2)
            write_C(val, buf)
        elif tag == 'OPAQUE':
            buf.append(val)
        else:
            raise ValueError(f'V: bad tag {tag!r}')
    buf.append(0)  # V 终止符


def read_G(r):
    """G (group): (C-expr + cont_byte)+, cont=0 结束"""
    items = []
    while True:
        expr = read_C(r)
        if r.eof():
            raise ValueError(f'G: EOF expecting cont at 0x{r.pos:x}')
        cont = r.u8()
        items.append((expr, cont))
        if cont == 0:
            return items


def write_G(items, buf):
    for expr, cont in items:
        write_C(expr, buf)
        buf.append(cont)


def read_S(r):
    """S 字符串, 0 终止. SJIS 双字节处理: lead 后跳一字节, 防止第二字节=0 截断"""
    start = r.pos
    while True:
        if r.eof():
            raise ValueError(f'S: EOF at 0x{r.pos:x}')
        b = r.u8()
        if b == 0:
            break
        if is_sjis_lead(b):
            if r.eof():
                raise ValueError(f'S: SJIS trail EOF at 0x{r.pos:x}')
            r.u8()
    return bytes(r.data[start : r.pos - 1])


def write_S(s, buf):
    buf += s
    buf.append(0)


# ---------------------------------------------------------------------------
# 隐式 TEXT run (主分发器 default 路径: SJIS → FUN_00404550, 其他 → FUN_00404780)
# ---------------------------------------------------------------------------
def read_sjis_run(r):
    """SJIS run: 循环
       peek == 0 → consume, return (含 0)
       peek in (0x81-9F/E0-EF/FA-FC) → consume 2 字节 (lead + trail)
       else → return (不 consume, 让主分发器处理)"""
    start = r.pos
    while not r.eof():
        b = r.peek()
        if b == 0:
            r.u8()
            return bytes(r.data[start : r.pos - 1]), True
        if is_sjis_lead(b):
            r.u8()
            if r.eof():
                return bytes(r.data[start : r.pos]), False
            r.u8()
            continue
        return bytes(r.data[start : r.pos]), False
    return bytes(r.data[start : r.pos]), False


def read_text2_run(r):
    """TEXT2 run (半角): 循环
       peek == 0 → consume, return
       peek in (0x81-9F) → return (不 consume)
       peek in (0xE0-0xEF) → return (不 consume)
       else → consume 1 字节"""
    start = r.pos
    while not r.eof():
        b = r.peek()
        if b == 0:
            r.u8()
            return bytes(r.data[start : r.pos - 1]), True
        if 0x81 <= b <= 0x9F:
            return bytes(r.data[start : r.pos]), False
        if 0xE0 <= b <= 0xEF:
            return bytes(r.data[start : r.pos]), False
        r.u8()
    return bytes(r.data[start : r.pos]), False


# ---------------------------------------------------------------------------
# 指令级参数
# ---------------------------------------------------------------------------
def read_args(r, fmt):
    args = []
    for c in fmt:
        if c == 'B':   args.append(r.u8())
        elif c == 'H': args.append(r.u16())
        elif c == 'I': args.append(r.u32())
        elif c == 'S': args.append(read_S(r))
        elif c == 'C': args.append(read_C(r))
        elif c == 'V': args.append(read_V(r))
        elif c == 'G': args.append(read_G(r))
        else: raise ValueError(f'unknown fmt char {c!r}')
    return args


def write_args(args, fmt, buf):
    ai = 0
    for c in fmt:
        v = args[ai]; ai += 1
        if c == 'B':   buf.append(v)
        elif c == 'H': buf += struct.pack('<H', v)
        elif c == 'I': buf += struct.pack('<I', v)
        elif c == 'S': write_S(v, buf)
        elif c == 'C': write_C(v, buf)
        elif c == 'V': write_V(v, buf)
        elif c == 'G': write_G(v, buf)
        else: raise ValueError(f'unknown fmt {c!r}')


# ---------------------------------------------------------------------------
# 反汇编 / 重汇编
# ---------------------------------------------------------------------------
# 指令形式:
#   ('OP',   pos, op_byte, name, args)
#   ('SJIS', pos, bytes, has_terminator)
#   ('TEXT2',pos, bytes, has_terminator)
def disassemble(data):
    r = Reader(data)
    insns = []
    while not r.eof():
        pos = r.pos
        b = r.peek()
        if b in OPCODES:
            r.u8()
            name, fmt = OPCODES[b]
            try:
                args = read_args(r, fmt)
            except Exception as e:
                raise RuntimeError(f'0x{pos:06x}: op 0x{b:02x} {name} parse error: {e}')
            insns.append(('OP', pos, b, name, args))
        elif is_sjis_lead(b):
            run, term = read_sjis_run(r)
            insns.append(('SJIS', pos, run, term))
        else:
            run, term = read_text2_run(r)
            insns.append(('TEXT2', pos, run, term))
    return insns


def assemble(insns):
    buf = bytearray()
    for insn in insns:
        kind = insn[0]
        if kind == 'OP':
            _, _, op, name, args = insn
            buf.append(op)
            fmt = OPCODES[op][1]
            write_args(args, fmt, buf)
        elif kind in ('SJIS', 'TEXT2'):
            _, _, run, term = insn
            buf += run
            if term:
                buf.append(0)
        else:
            raise ValueError(f'unknown insn kind {kind!r}')
    return bytes(buf)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli():
    import sys, hashlib, os
    if len(sys.argv) < 3:
        print('usage:')
        print('  ai5v7_bytecode_v2.py decompress <file.mes> <out>      # 仅解压 LZSS')
        print('  ai5v7_bytecode_v2.py dump       <file.mes>            # 解压+反汇编并打印')
        print('  ai5v7_bytecode_v2.py verify     <file.mes>            # round-trip 字节级校验')
        print('  ai5v7_bytecode_v2.py verify-dir <dir>                 # 批量 round-trip')
        return

    cmd = sys.argv[1]
    path = sys.argv[2]

    if cmd == 'decompress':
        with open(path, 'rb') as f:
            raw = f.read()
        out = lzss_decompress(raw)
        with open(sys.argv[3], 'wb') as f:
            f.write(out)
        print(f'{path}: {len(raw)} -> {len(out)} bytes, {len(out)/len(raw):.2f}x')

    elif cmd == 'dump':
        with open(path, 'rb') as f:
            raw = f.read()
        plain = lzss_decompress(raw)
        insns = disassemble(plain)
        print(f'{path}: compressed={len(raw)} plain={len(plain)} instructions={len(insns)}')
        for insn in insns:
            kind, pos = insn[0], insn[1]
            if kind == 'OP':
                _, _, op, name, args = insn
                s = repr(args)
                if len(s) > 120: s = s[:117] + '...'
                print(f'  0x{pos:06x}: op=0x{op:02x} {name:15} {s}')
            elif kind == 'SJIS':
                _, _, run, term = insn
                try:
                    t = run.decode('cp932')
                    if len(t) > 40: t = t[:40] + '...'
                    print(f'  0x{pos:06x}: SJIS   {t!r}' + (' <0>' if term else ''))
                except:
                    print(f'  0x{pos:06x}: SJIS   <{run.hex()}>' + (' <0>' if term else ''))
            else:
                _, _, run, term = insn
                try:
                    t = run.decode('cp932', errors='replace')
                    if len(t) > 40: t = t[:40] + '...'
                    print(f'  0x{pos:06x}: TEXT2  {t!r}' + (' <0>' if term else ''))
                except:
                    print(f'  0x{pos:06x}: TEXT2  <{run.hex()}>' + (' <0>' if term else ''))

    elif cmd == 'verify':
        with open(path, 'rb') as f:
            raw = f.read()
        plain = lzss_decompress(raw)
        try:
            insns = disassemble(plain)
        except Exception as e:
            print(f'{path}: DISASM FAIL: {e}')
            return
        rebuilt = assemble(insns)
        ok = (plain == rebuilt)
        a = hashlib.md5(plain).hexdigest()
        b = hashlib.md5(rebuilt).hexdigest()
        print(f'{path}: plain={len(plain)} rebuilt={len(rebuilt)} '
              f'md5 orig={a[:8]} new={b[:8]} insns={len(insns)} {"OK" if ok else "MISMATCH"}')
        if not ok:
            for i, (x, y) in enumerate(zip(plain, rebuilt)):
                if x != y:
                    print(f'  首个差异 @ 0x{i:x}: {x:02x} vs {y:02x}')
                    print(f'  原始 ctx: {plain[max(0,i-8):i+16].hex()}')
                    print(f'  重建 ctx: {rebuilt[max(0,i-8):i+16].hex()}')
                    break
            if len(plain) != len(rebuilt):
                print(f'  长度不同: {len(plain)} vs {len(rebuilt)}')

    elif cmd == 'verify-dir':
        ok_c, fail_c = 0, 0
        fail_list = []
        files = sorted(f for f in os.listdir(path) if f.upper().endswith('.MES'))
        for name in files:
            fp = os.path.join(path, name)
            with open(fp, 'rb') as f:
                raw = f.read()
            try:
                plain = lzss_decompress(raw)
                insns = disassemble(plain)
                rebuilt = assemble(insns)
                if plain == rebuilt:
                    ok_c += 1
                else:
                    fail_c += 1
                    # 找首差
                    for i, (x, y) in enumerate(zip(plain, rebuilt)):
                        if x != y:
                            fail_list.append((name, f'byte mismatch @ 0x{i:x}'))
                            break
                    else:
                        fail_list.append((name, f'length mismatch {len(plain)} vs {len(rebuilt)}'))
            except Exception as e:
                fail_c += 1
                fail_list.append((name, str(e)[:80]))
        print(f'\n结果: {ok_c} OK / {fail_c} FAIL / {len(files)} total')
        for n, r in fail_list[:30]:
            print(f'  FAIL: {n}  {r}')
        if len(fail_list) > 30:
            print(f'  ... 还有 {len(fail_list)-30} 个')


if __name__ == '__main__':
    _cli()