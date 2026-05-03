#!/usr/bin/env python3
"""AI5WIN v2 MES 脚本反汇编共用模块 (あしたの雪之丞2 等)

基于 ai5win.exe 权威反汇编 (FUN_00416900 主循环 + FUN_004070f0 派发器
  + FUN_004019c0 slot_list + FUN_00416e00 expr 栈VM)

主循环:
  peek == 0x01 → OP_01 TEXT      (双字节全角, 循环读直到 0x00)
  peek == 0x02 → OP_02 SYS_TEXT  (单字节半角, 遇 0x00/0x80-9F/0xE0-EF 停)
  else         → FUN_004070f0 派发 op 0x00..0x18

expr 栈VM (以 0xFF 结束):
  0x00..0x7F: push byte 立即数 (0 字节额外)
  0x80..0x9F: W_FLAG  (1 字节)
  0xA0..0xBF: A_FLAG  (1 字节)
  0xC0..0xDF: PC_FLAG (1 字节)
  0xE0..0xF0: 算术/比较 (0 字节)
  0xF1/0xF3:  u16 (2 字节)
  0xF2:       u32 (4 字节)
  0xF4:       pop (0 字节)
  0xF5..0xF8: (1 字节)
  0xFF:       STRUCT_END

slot_list (以 0x00 结束):
  consume tag; tag==0x01: NUL 终结字串; tag==0x02: expr; 其它: 丢弃;
  循环直到 peek == 0 (consume 终止 0)

u32 跳转载体 (真 PC 跳转):
  op 0x09 PW_FLAG: expr + [u32]       (条件跳转: expr!=1时 PC=u32)
  op 0x0a PB_FLAG: [u32]              (无条件跳转: PC=u32)
  op 0x0e CH_POS : slot_list + [u32]  (菜单项跳转: 选中时 PC=u32)

其它 op 的 IMM4 或 expr 内 F2 是数据常量, 不是 PC 跳转.
"""

import struct


# ─── LZSS ───
def lzss_decompress(src):
    out = bytearray(); window = bytearray(b'\x00' * 4096); wp = 0xFEE; sp = 0
    while sp < len(src):
        flags = src[sp]; sp += 1
        for bit in range(8):
            if sp >= len(src): break
            if flags & (1 << bit):
                b = src[sp]; sp += 1; out.append(b); window[wp] = b; wp = (wp+1) & 0xFFF
            else:
                if sp + 1 >= len(src): break
                lo = src[sp]; hi = src[sp+1]; sp += 2
                off = lo | ((hi & 0xF0) << 4); ml = (hi & 0x0F) + 3
                for k in range(ml):
                    b = window[(off+k) & 0xFFF]; out.append(b); window[wp] = b
                    wp = (wp+1) & 0xFFF
    return bytes(out)


def lzss_compress_fake(data):
    """"假"LZSS - 每8字节一组 flag=0xFF (全字面量), 引擎能正常解."""
    out = bytearray(); i = 0; n = len(data)
    while i < n:
        chunk = data[i:i+8]
        out.append(0xFF)
        out += chunk + b'\x00' * (8 - len(chunk))
        i += 8
    return bytes(out)


# ─── expr 字节消耗 ───
_EXPR_READ = {}
for _b in range(0x00, 0x80): _EXPR_READ[_b] = 0   # push byte
for _b in range(0x80, 0xA0): _EXPR_READ[_b] = 1
for _b in range(0xA0, 0xC0): _EXPR_READ[_b] = 1
for _b in range(0xC0, 0xE0): _EXPR_READ[_b] = 1
for _b in range(0xE0, 0xF1): _EXPR_READ[_b] = 0
_EXPR_READ[0xF1] = 2; _EXPR_READ[0xF2] = 4; _EXPR_READ[0xF3] = 2
_EXPR_READ[0xF4] = 0; _EXPR_READ[0xF5] = 1; _EXPR_READ[0xF6] = 1
_EXPR_READ[0xF7] = 1; _EXPR_READ[0xF8] = 1


def read_expr(bc, p, end_limit):
    """读一个 expr (至 0xFF). 返回 (new_p, expr内F2u32位置列表)."""
    u32_positions = []
    max_iter = 2000
    while p < end_limit and max_iter > 0:
        max_iter -= 1
        b = bc[p]
        if b == 0xFF:
            return p + 1, u32_positions
        if b == 0xF2:
            u32_positions.append(p + 1)
        nread = _EXPR_READ.get(b)
        if nread is None:
            # 未知字节容错退出
            return p + 1, u32_positions
        p += 1 + nread
    return p, u32_positions


def read_slot_list(bc, p, end_limit):
    """读 slot_list (至 0x00). 返回 (new_p, slots, u32_positions).
    slots[i] = ('STR', abs_pos, byte_len, str_bytes)
             | ('EXPR', abs_pos, byte_len, None)
             | ('EMPTY', tag_pos, 1, tag_bytes)
    """
    slots = []
    u32s = []
    max_iter = 1000
    while p < end_limit and max_iter > 0:
        max_iter -= 1
        if bc[p] == 0:
            return p + 1, slots, u32s
        tag = bc[p]; p += 1
        if tag == 0x01:
            e = bc.find(b'\x00', p, end_limit)
            if e < 0:
                slots.append(('STR', p, end_limit - p, bc[p:end_limit]))
                return end_limit, slots, u32s
            slots.append(('STR', p, e - p, bc[p:e]))
            p = e + 1
        elif tag == 0x02:
            s = p
            p, u = read_expr(bc, p, end_limit)
            slots.append(('EXPR', s, p - s, None))
            u32s.extend(u)
        else:
            slots.append(('EMPTY', p - 1, 1, bytes([tag])))
    return p, slots, u32s


# ─── OP handlers ───
# 每个 handler 签名: fn(bc, p, end) -> (new_p, args_list, u32_positions)
# args_list 元素: (typ, abs_pos, byte_len, value)

def h_00(bc, p, end):
    return p, [('NONE', 0, 0, None)], []


def _is_cp932_lead_byte(b):
    return (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC)


def h_01(bc, p, end):
    """TEXT: 双字节 CP932 文本循环。

    新版工作流采用 CP932 借码位，不再把 GBK 字节混入 op 0x01，
    所以这里恢复为 CP932 lead-byte 判断，减少误识别。
    """
    start = p
    while p < end:
        b = bc[p]
        if b == 0:
            return p + 1, [('TEXT', start, p - start, bc[start:p]),
                           ('TERM', p, 1, bytes([0]))], []
        if not _is_cp932_lead_byte(b):
            return p, [('TEXT', start, p - start, bc[start:p]),
                       ('TERM', p, 0, b'')], []
        if p + 1 >= end:
            return p, [('TEXT', start, p - start, bc[start:p]),
                       ('TERM', p, 0, b'')], []
        p += 2
    return p, [('TEXT', start, p - start, bc[start:p]),
               ('TERM', p, 0, b'')], []


def h_02(bc, p, end):
    """SYS_TEXT: 单字节循环"""
    start = p
    while p < end:
        b = bc[p]
        if b == 0:
            return p + 1, [('TEXT', start, p - start, bc[start:p]),
                           ('TERM', p, 1, bytes([0]))], []
        if (0x80 <= b <= 0x9F) or (0xE0 <= b <= 0xEF):
            return p, [('TEXT', start, p - start, bc[start:p]),
                       ('TERM', p, 0, b'')], []
        p += 1
    return p, [('TEXT', start, p - start, bc[start:p]),
               ('TERM', p, 0, b'')], []


def _flag_set_loop(bc, p, end, exprs, u32s):
    """consume-then-check 循环: consume 1 byte; 非0则读 expr, 重复"""
    while p < end:
        ctrl = bc[p]; p += 1
        if ctrl == 0: break
        s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    return p


def h_03(bc, p, end):
    """B_FLAG_SET: <id:u16> expr (byte expr)* byte=0"""
    if p + 2 > end: return p, [], []
    id_bytes = bc[p:p+2]; p += 2
    exprs = []; u32s = []
    s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    p = _flag_set_loop(bc, p, end, exprs, u32s)
    return p, [('ID16', 0, 2, id_bytes), ('EXPRS', 0, 0, exprs)], u32s


def h_04(bc, p, end):
    """W_FLAG_SET: <id:u8> expr (byte expr)* byte=0"""
    if p + 1 > end: return p, [], []
    id_byte = bc[p:p+1]; p += 1
    exprs = []; u32s = []
    s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    p = _flag_set_loop(bc, p, end, exprs, u32s)
    return p, [('ID8', 0, 1, id_byte), ('EXPRS', 0, 0, exprs)], u32s


def h_05(bc, p, end):
    """EXT_B_FLAG_SET: expr expr (byte expr)* byte=0"""
    exprs = []; u32s = []
    s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    p = _flag_set_loop(bc, p, end, exprs, u32s)
    return p, [('EXPRS', 0, 0, exprs)], u32s


def h_06_07_08(bc, p, end):
    """PC/A/G_FLAG_SET: expr <u8> expr (byte expr)* byte=0"""
    exprs = []; u32s = []
    s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    sel = bc[p:p+1] if p < end else b''
    if p < end: p += 1
    s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    p = _flag_set_loop(bc, p, end, exprs, u32s)
    return p, [('SEL', 0, 1, sel), ('EXPRS', 0, 0, exprs)], u32s


def h_09(bc, p, end):
    """PW_FLAG (条件跳转): expr + [u32]"""
    s = p; p, u32s = read_expr(bc, p, end)
    if p + 4 > end:
        return p, [('EXPR', s, p-s, None)], list(u32s)
    imm_pos = p; imm = bc[p:p+4]; p += 4
    return p, [('EXPR', s, imm_pos - s, None),
               ('IMM4', imm_pos, 4, imm)], list(u32s)


def h_0a(bc, p, end):
    """PB_FLAG (无条件跳转): [u32]"""
    if p + 4 > end: return p, [], []
    imm_pos = p; imm = bc[p:p+4]; p += 4
    return p, [('IMM4', imm_pos, 4, imm)], []


def h_0b(bc, p, end):
    """op 0x0b: expr(subcmd) + slot_list (无跳转 IMM4)"""
    s = p; p, u_e = read_expr(bc, p, end)
    p2, slots, u_s = read_slot_list(bc, p, end)
    return p2, [('EXPR', s, p-s, None), ('SLOTS', p, p2-p, slots)], list(u_e) + list(u_s)


def h_0c(bc, p, end):
    """JUMP (文件名跳转): slot_list"""
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


def h_0d(bc, p, end):
    """SYS: slot_list"""
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


def h_0e(bc, p, end):
    """CH_POS (菜单项跳转): slot_list + [u32]"""
    p2, slots, u32s = read_slot_list(bc, p, end)
    if p2 + 4 > end:
        return p2, [('SLOTS', p, p2-p, slots)], u32s
    imm_pos = p2; imm = bc[p2:p2+4]; p3 = p2 + 4
    return p3, [('SLOTS', p, p2-p, slots), ('IMM4', imm_pos, 4, imm)], u32s


def h_0f(bc, p, end):
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


def h_10(bc, p, end):
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


def h_11(bc, p, end):
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


def h_12(bc, p, end):
    """SPEC_SYS: <u8> expr (byte expr)* byte=0"""
    if p + 1 > end: return p, [], []
    id_byte = bc[p:p+1]; p += 1
    exprs = []; u32s = []
    s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    p = _flag_set_loop(bc, p, end, exprs, u32s)
    return p, [('ID8', 0, 1, id_byte), ('EXPRS', 0, 0, exprs)], u32s


def h_13(bc, p, end):
    """NEW_LINE: 0 字节"""
    return p, [], []


def h_14(bc, p, end):
    """INT_IF: <u8> expr (byte expr)* byte=0"""
    if p + 1 > end: return p, [], []
    id_byte = bc[p:p+1]; p += 1
    exprs = []; u32s = []
    s = p; p, u = read_expr(bc, p, end); exprs.append((s, p-s)); u32s.extend(u)
    p = _flag_set_loop(bc, p, end, exprs, u32s)
    return p, [('ID8', 0, 1, id_byte), ('EXPRS', 0, 0, exprs)], u32s


def h_15(bc, p, end):
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


def h_16(bc, p, end):
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


def h_17(bc, p, end):
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


def h_18(bc, p, end):
    p2, slots, u32s = read_slot_list(bc, p, end)
    return p2, [('SLOTS', p, p2-p, slots)], u32s


OP_HANDLERS = {
    0x00: h_00, 0x01: h_01, 0x02: h_02, 0x03: h_03, 0x04: h_04,
    0x05: h_05, 0x06: h_06_07_08, 0x07: h_06_07_08, 0x08: h_06_07_08,
    0x09: h_09, 0x0a: h_0a, 0x0b: h_0b, 0x0c: h_0c, 0x0d: h_0d,
    0x0e: h_0e, 0x0f: h_0f, 0x10: h_10, 0x11: h_11, 0x12: h_12,
    0x13: h_13, 0x14: h_14, 0x15: h_15, 0x16: h_16, 0x17: h_17,
    0x18: h_18,
}

OP_NAME = {
    0x00: 'RETURN', 0x01: 'TEXT', 0x02: 'SYS_TEXT',
    0x03: 'B_FLAG_SET', 0x04: 'W_FLAG_SET', 0x05: 'EXT_B_FLAG',
    0x06: 'PC_FLAG', 0x07: 'A_FLAG', 0x08: 'G_FLAG',
    0x09: 'PW_FLAG', 0x0a: 'PB_FLAG', 0x0b: 'OP_0B',
    0x0c: 'JUMP', 0x0d: 'SYS', 0x0e: 'CH_POS',
    0x0f: 'CALL', 0x10: 'MENU_SET', 0x11: 'INTERRUPT',
    0x12: 'SPEC_SYS', 0x13: 'NEW_LINE', 0x14: 'INT_IF',
    0x15: 'MENU', 0x16: 'FLAG_D_SET', 0x17: 'MESSAGE',
    0x18: 'NOP',
}

# 真 PC 跳转 op (IMM4 必须在变长注入时修正)
JUMP_OPS = {0x09, 0x0a, 0x0e}


def disasm(bc, start, end):
    """反汇编 [start, end) 区间.
    返回 list of (abs_offset, op, args_list, u32_positions)
    op == 0xFF 表示未识别
    """
    p = start
    result = []
    last_p = -1
    stuck = 0
    while p < end:
        if p == last_p:
            stuck += 1
            if stuck > 2:
                result.append((p, 0xFF, [('UNK', p, 1, bytes([bc[p]]))], []))
                p += 1
                stuck = 0
                continue
        last_p = p
        op = bc[p]
        if op not in OP_HANDLERS:
            result.append((p, 0xFF, [('UNK', p, 1, bytes([op]))], []))
            p += 1
            continue
        op_start = p
        p += 1
        try:
            p, args, u32s = OP_HANDLERS[op](bc, p, end)
        except Exception as e:
            result.append((op_start, 0xFF, [('ERR', op_start, 1, str(e).encode()[:30])], []))
            p = op_start + 1
            continue
        result.append((op_start, op, args, u32s))
    return result


def extract_jump_targets(lines):
    """提取所有 IMM4 跳转载体 (op 0x09/0x0a/0x0e 的 u32).
    返回: [(abs_position_of_u32, current_value, op)]
    """
    targets = []
    for (off, op, args, _) in lines:
        if op not in JUMP_OPS:
            continue
        for (typ, ps, sz, val) in args:
            if typ == 'IMM4' and val and len(val) == 4:
                imm_val = int.from_bytes(val, 'little')
                targets.append((ps, imm_val, op))
                break
    return targets


def parse_mes(dec):
    """读 MES 头 + 反汇编整段.
    返回 (mc, hs, msg_rel, msg_abs, lines)
    """
    mc = struct.unpack_from('<I', dec, 0)[0]
    hs = 4 + mc * 4
    msg_rel = [struct.unpack_from('<I', dec, 4 + i*4)[0] for i in range(mc)]
    msg_abs = [r + hs for r in msg_rel]
    lines = disasm(dec, hs, len(dec))
    return mc, hs, msg_rel, msg_abs, lines


# ─── CLI ───
def _fmt_args(args):
    parts = []
    for (typ, ps, sz, val) in args:
        if typ == 'TEXT':
            try: s = val.decode('cp932')
            except: s = val.hex()
            parts.append(f"TEXT[{len(val)}B]: {s!r}")
        elif typ == 'SLOTS':
            sd = []
            for sl in val:
                if sl[0] == 'STR':
                    try: s = sl[3].decode('cp932')
                    except: s = sl[3].hex()
                    sd.append(f"STR({s!r})")
                elif sl[0] == 'EXPR':
                    sd.append(f"EXPR({sl[2]}B)")
                elif sl[0] == 'EMPTY':
                    sd.append(f"T{sl[3][0]:02X}")
            parts.append('{' + ','.join(sd) + '}')
        elif typ == 'IMM4':
            v = int.from_bytes(val, 'little')
            parts.append(f"IMM4=0x{v:X}")
        elif typ == 'EXPR': parts.append('expr')
        elif typ == 'EXPRS': parts.append(f'{len(val)}exprs')
        elif typ == 'ID8': parts.append(f'id={val[0]}')
        elif typ == 'ID16': parts.append(f'id={int.from_bytes(val,"little")}')
        elif typ == 'SEL':
            if val: parts.append(f'sel={val[0]:02X}')
        elif typ in ('TERM','NONE'): pass
        else: parts.append(typ)
    return '  '.join(parts)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("usage: python ai5win_disasm.py <mes_path> [id]")
        sys.exit(1)
    path = sys.argv[1]
    target_id = int(sys.argv[2]) if len(sys.argv) > 2 else None
    dec = lzss_decompress(open(path, 'rb').read())
    mc, hs, msg_rel, msg_abs, lines = parse_mes(dec)
    print(f"=== {path}  mc={mc}  hs={hs}  dec_size={len(dec)} ===")
    if target_id is not None:
        a = msg_abs[target_id]
        e = msg_abs[target_id+1] if target_id+1 < mc else len(dec)
        print(f"\nid={target_id}  abs=[0x{a:X}-0x{e:X}]  len={e-a}")
        for (off, op, args, _) in lines:
            if not (a <= off < e): continue
            rel = off - a
            name = OP_NAME.get(op, f'?{op:02X}')
            print(f"  +{rel:3d} (0x{off:05X})  0x{op:02X} {name:12s} {_fmt_args(args)}")
    else:
        unk = sum(1 for (_,op,_,_) in lines if op == 0xFF)
        jmps = extract_jump_targets(lines)
        print(f"  ops: {len(lines)}  UNK: {unk}  跳转载体: {len(jmps)}")
        for (pos, val, op) in jmps[:20]:
            name = OP_NAME.get(op, '?')
            print(f"    @0x{pos:05X}  val=0x{val:X}  by {name}")
