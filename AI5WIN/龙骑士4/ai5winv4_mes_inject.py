#!/usr/bin/env python3
"""AI5WIN v4 MES 文本注入工具
适配 GalTransl JSON: {id, name, message}
变长替换 + header msg_offsets 修正 + bytecode 跳转地址精确修正。

跳转地址识别 (从 AI5WINV4.exe 逆向 + version 2 opcode 表):
  完整 opcode 解析器遍历字节码, 精确定位所有含 I (u32) 地址参数的指令:
    0x0b CI JUMP_IF      → arg[1] = 跳转地址
    0x0c I  JUMP         → arg[0] = 跳转地址
    0x10 VI MENU_SET     → arg[1] = 跳转地址
    0x14 CI INTERRUPT_IF → arg[1] = 跳转地址
    0x1c CI              → arg[1] = 跳转地址
    0x1f I  LABEL        → arg[0] = 跳转地址
  所有地址值均相对于 header 末尾 (bytecode 区起始)。

用法:
  python ai5winv4_mes_inject.py <input.mes> <trans.json> [output.mes]
  python ai5winv4_mes_inject.py <mes_dir>   <json_dir>   [output_dir]  (批量)
"""
import struct, json, sys, os

# ── 编码 ──
SPECIAL_CHAR_MAP = {
    '♡': b'\xFE\x50',
    '♪': b'\xFE\x51',
    '・': b'\xFE\x52',
}

def encode_text(s, encoding='cp932'):
    """将 Unicode 文本编码为游戏引擎可用的字节序列。
    默认 cp932 编码, 回退 gbk。可通过 --encoding gbk 切换。
    半角ASCII自动转全角。
    """
    fallback = 'gbk' if encoding == 'cp932' else 'cp932'
    out = bytearray()
    for c in s:
        if c == ' ':
            c = '\u3000'
        elif '!' <= c <= '~':
            c = chr(ord(c) - 0x21 + 0xFF01)
        if c in SPECIAL_CHAR_MAP:
            out += SPECIAL_CHAR_MAP[c]
        else:
            try:
                out += c.encode(encoding)
            except:
                try:
                    out += c.encode(fallback)
                except:
                    out += b'?'
    return bytes(out)

# ── LZSS ──
def lzss_decompress(src):
    out = bytearray(); window = bytearray(b'\x00' * 4096); wp = 0xFEE; sp = 0
    while sp < len(src):
        flags = src[sp]; sp += 1
        for bit in range(8):
            if sp >= len(src): break
            if flags & (1 << bit):
                b = src[sp]; sp += 1; out.append(b); window[wp] = b; wp = (wp + 1) & 0xFFF
            else:
                if sp + 1 >= len(src): break
                lo = src[sp]; hi = src[sp + 1]; sp += 2
                off = lo | ((hi & 0xF0) << 4); ml = (hi & 0x0F) + 3
                for k in range(ml):
                    b = window[(off + k) & 0xFFF]; out.append(b); window[wp] = b; wp = (wp + 1) & 0xFFF
    return bytes(out)

def lzss_compress_fake(data):
    """Fake LZSS 压缩 (纯字面量, 无匹配引用)"""
    out = bytearray(); i = 0; n = len(data)
    while i < n:
        chunk = data[i:i + 8]
        out.append(0xFF)
        out += chunk + b'\x00' * (8 - len(chunk))
        i += 8
    return bytes(out)

# ── Opcode 解析器 (version 2) ──
CMD_ARGS = {
    0x00: '',       0x01: 'S',      0x02: 'S',      0x03: 'HCG',
    0x04: 'BCG',    0x05: 'CCG',    0x06: 'CBCG',   0x07: 'CBCG',
    0x08: 'CFCG',   0x09: 'CBCG',   0x0a: 'CBCG',   0x0b: 'CI',
    0x0c: 'I',      0x0d: 'CV',     0x0e: 'V',      0x0f: 'V',
    0x10: 'VI',     0x11: 'V',      0x12: 'V',      0x13: 'B',
    0x14: 'CI',     0x15: 'CG',     0x16: 'BCG',    0x17: 'I',
    0x18: '',       0x1b: 'CG',     0x1c: 'CI',     0x1d: 'CG',
    0x1f: 'I',
}

# 哪些 opcode 的第几个参数是跳转地址
JUMP_OPS = {0x0b: 1, 0x0c: 0, 0x10: 1, 0x14: 1, 0x1c: 1, 0x1f: 0}

def _skip_struct(dec, pos):
    """跳过 C struct, 返回 0xFF STRUCT_END 之后的位置"""
    while pos < len(dec):
        sb = dec[pos]; pos += 1
        if sb == 0xFF:
            return pos
        elif 0x80 <= sb <= 0xBF:
            pos += 1
        elif 0xE0 <= sb <= 0xF0:
            pass
        elif sb == 0xF1:
            pos += 2
        elif sb == 0xF2:
            pos += 4
        elif sb == 0xF3:
            pos += 2
        elif sb == 0xF4:
            pass
        elif 0xF5 <= sb <= 0xF8:
            pos += 1
    return pos

def _skip_var(dec, pos):
    """跳过 V variable structure"""
    while pos < len(dec):
        definer = dec[pos]; pos += 1
        if definer == 0:
            return pos
        elif definer == 1:
            end = dec.find(b'\x00', pos)
            if end < 0: return len(dec)
            pos = end + 1
        elif definer == 2:
            pos = _skip_struct(dec, pos)
    return pos

def _skip_group(dec, pos):
    """跳过 G group structure"""
    while pos < len(dec):
        flag = dec[pos]; pos += 1
        if flag == 0:
            return pos
        pos = _skip_struct(dec, pos)
    return pos

def find_jump_addrs(dec, hs):
    """精确遍历字节码, 定位所有跳转地址的 (file_pos, rel_value)"""
    addrs = []
    pos = hs
    while pos < len(dec):
        op = dec[pos]
        if op not in CMD_ARGS:
            pos += 1; continue
        args_fmt = CMD_ARGS[op]
        pos += 1
        arg_idx = 0
        for ch in args_fmt:
            if ch == 'I':
                val = struct.unpack_from('<I', dec, pos)[0]
                if op in JUMP_OPS and JUMP_OPS[op] == arg_idx:
                    addrs.append((pos, val))
                pos += 4; arg_idx += 1
            elif ch == 'H':
                pos += 2; arg_idx += 1
            elif ch == 'B':
                pos += 1; arg_idx += 1
            elif ch == 'S':
                end = dec.find(b'\x00', pos)
                if end < 0: pos = len(dec); break
                pos = end + 1; arg_idx += 1
            elif ch == 'C':
                pos = _skip_struct(dec, pos); arg_idx += 1
            elif ch == 'V':
                pos = _skip_var(dec, pos); arg_idx += 1
            elif ch == 'G':
                pos = _skip_group(dec, pos); arg_idx += 1
            elif ch == 'F':
                if dec[pos] != 0:
                    break
                pos += 1; arg_idx += 1
    return addrs

# ── 消息解析 ──
def parse_messages(dec, mc, hs):
    """解析所有 message block, 返回可替换文本的位置信息列表"""
    msgs = []
    for mi in range(mc):
        rel = struct.unpack_from('<I', dec, 4 + mi * 4)[0]
        abs_pos = rel + hs

        if abs_pos >= len(dec) or dec[abs_pos] != 0x17:
            msgs.append(None); continue

        pos = abs_pos + 5

        if mi + 1 < mc:
            next_rel = struct.unpack_from('<I', dec, 4 + (mi + 1) * 4)[0]
            block_end = next_rel + hs
        else:
            block_end = len(dec)

        name_span = None  # (start, end) 不含 opcode 和 \x00
        msg_span = None
        first_text = True

        while pos < block_end:
            op = dec[pos]
            if op == 0x01:
                str_start = pos + 1
                str_end = dec.find(b'\x00', str_start)
                if str_end < 0:
                    break
                raw = dec[str_start:str_end]

                if first_text:
                    first_text = False
                    try:
                        text = raw.decode('cp932')
                    except:
                        pos = str_end + 1; continue

                    if (text.startswith('［') and '］' in text):
                        # 名前部分嵌在第一个 TEXT string 内
                        # 整个 string 包含 ［name］ + 可能的尾部文本
                        # 但实际上名前和台词分在两个 TEXT 里
                        name_span = (str_start, str_end)
                    elif (text.startswith('【') and '】' in text):
                        name_span = (str_start, str_end)
                    else:
                        msg_span = (str_start, str_end)
                else:
                    msg_span = (str_start, str_end)

                pos = str_end + 1
            elif op == 0x13:
                pos += 2
            else:
                break

        if msg_span or name_span:
            msgs.append({
                'rel': rel,
                'name': name_span,
                'msg': msg_span if msg_span else name_span,
            })
        else:
            msgs.append(None)
    return msgs

# ── 注入 ──
def inject_file(mes_path, json_path, out_path, encoding='cp932'):
    compressed = open(mes_path, 'rb').read()
    dec = bytearray(lzss_decompress(compressed))
    mc = struct.unpack_from('<I', dec, 0)[0]
    hs = 4 + mc * 4

    with open(json_path, 'r', encoding='utf-8') as f:
        trans = json.load(f)
    td = {e['id']: e for e in trans}
    msgs = parse_messages(dec, mc, hs)

    # 构建替换列表: (start, end, new_bytes)
    replacements = []
    replaced_count = 0
    for i, m in enumerate(msgs):
        if m is None or i not in td:
            continue
        e = td[i]
        new_msg = e.get('message', '')
        new_name = e.get('name', '')

        # 名前替换
        if m['name'] is not None and new_name:
            old_nb = dec[m['name'][0]:m['name'][1]]
            try:
                old_name_str = old_nb.decode('cp932')
            except:
                old_name_str = None
            # 重建带括号的完整名前字符串
            if old_name_str:
                # 检测括号类型
                if old_name_str.startswith('［'):
                    bracket_l, bracket_r = '［', '］'
                elif old_name_str.startswith('【'):
                    bracket_l, bracket_r = '【', '】'
                else:
                    bracket_l, bracket_r = '', ''

                if bracket_l:
                    old_inner = old_name_str[1:old_name_str.index(bracket_r)]
                    if old_inner != new_name:
                        new_full = bracket_l + new_name + bracket_r
                        new_nb = encode_text(new_full, encoding)
                        replacements.append((m['name'][0], m['name'][1], new_nb))
                elif old_name_str != new_name:
                    new_nb = encode_text(new_name, encoding)
                    replacements.append((m['name'][0], m['name'][1], new_nb))

        # 台词替换
        if m['msg'] is not None and new_msg:
            old_mb = dec[m['msg'][0]:m['msg'][1]]
            try:
                old_msg_str = old_mb.decode('cp932')
            except:
                old_msg_str = None
            if old_msg_str != new_msg:
                new_mb = encode_text(new_msg, encoding)
                replacements.append((m['msg'][0], m['msg'][1], new_mb))
                replaced_count += 1

    replacements.sort(key=lambda x: x[0])

    if not replacements:
        open(out_path, 'wb').write(compressed)
        print(f"  {os.path.basename(mes_path)}: 无修改")
        return len(dec)

    # 在替换前找跳转地址 (使用原始 bytecode)
    jump_addrs = find_jump_addrs(bytes(dec), hs)

    # 重建 bytecode, 累积 delta
    new_bc = bytearray()
    delta = 0
    prev_end = hs
    breakpoints = []  # (old_abs_threshold, cumul_delta)

    for (rstart, rend, new_bytes) in replacements:
        new_bc += dec[prev_end:rstart]
        size_diff = len(new_bytes) - (rend - rstart)
        delta += size_diff
        breakpoints.append((rend, delta))
        new_bc += new_bytes
        prev_end = rend
    new_bc += dec[prev_end:]

    def remap_rel(old_rel):
        """将旧的相对偏移映射到新的相对偏移"""
        old_abs = old_rel + hs
        d = 0
        for (threshold, cumul_delta) in breakpoints:
            if old_abs >= threshold:
                d = cumul_delta
            else:
                break
        return old_rel + d

    # 重建 header msg_offsets
    new_header = struct.pack('<I', mc)
    for i in range(mc):
        old_rel = struct.unpack_from('<I', dec, 4 + i * 4)[0]
        new_header += struct.pack('<I', remap_rel(old_rel))

    # 精确修正跳转地址
    fixed = 0
    for (old_file_pos, old_val) in jump_addrs:
        new_val = remap_rel(old_val)
        if new_val == old_val:
            continue
        # 计算这个地址在新 bytecode 中的位置
        old_bc_offset = old_file_pos - hs
        d = 0
        for (threshold, cumul_delta) in breakpoints:
            if old_file_pos >= threshold:
                d = cumul_delta
            else:
                break
        new_bc_pos = old_bc_offset + d
        if 0 <= new_bc_pos <= len(new_bc) - 4:
            cur = struct.unpack_from('<I', new_bc, new_bc_pos)[0]
            if cur == old_val:
                struct.pack_into('<I', new_bc, new_bc_pos, new_val)
                fixed += 1

    # 输出
    plain = new_header + bytes(new_bc)
    result = lzss_compress_fake(plain)
    with open(out_path, 'wb') as f:
        f.write(result)

    d = len(result) - len(compressed)
    fn = os.path.basename(mes_path)
    print(f"  {fn}: {replaced_count} texts, {fixed} jumps fixed, "
          f"{len(compressed)}->{len(result)} ({'+' if d >= 0 else ''}{d})")
    return len(plain)

def main():
    # 解析 --encoding 参数
    args = sys.argv[1:]
    encoding = 'cp932'
    for i, a in enumerate(args):
        if a == '--encoding' and i + 1 < len(args):
            encoding = args[i + 1]
            args = args[:i] + args[i + 2:]
            break

    if len(args) < 2:
        print(__doc__)
        print("  --encoding <cp932|gbk>  指定输出编码 (默认 cp932)")
        sys.exit(1)

    src, jsrc = args[0], args[1]
    if os.path.isdir(src):
        od = args[2] if len(args) > 2 else src + '_patched'
        os.makedirs(od, exist_ok=True)
        for fn in sorted(os.listdir(src)):
            sp = os.path.join(src, fn); op = os.path.join(od, fn)
            if fn.startswith('_') or not fn.upper().endswith('.MES'):
                open(op, 'wb').write(open(sp, 'rb').read()); continue
            jp = os.path.join(jsrc, os.path.splitext(fn)[0] + '.json')
            if not os.path.exists(jp):
                open(op, 'wb').write(open(sp, 'rb').read()); continue
            try:
                inject_file(sp, jp, op, encoding)
            except Exception as e:
                print(f"  [ERROR] {fn}: {e}")
                import traceback; traceback.print_exc()
                open(op, 'wb').write(open(sp, 'rb').read())
        print(f"[完成] 编码: {encoding}")
    else:
        op = args[2] if len(args) > 2 else os.path.splitext(src)[0] + '_patched.mes'
        inject_file(src, jsrc, op, encoding)

if __name__ == '__main__':
    main()
