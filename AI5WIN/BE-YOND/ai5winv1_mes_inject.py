#!/usr/bin/env python3
"""AI5WIN v1 MES 文本注入工具
适配 GalTransl JSON: {id, name, message}
变长替换 + bytecode 跳转地址精确修正。

MES 格式 (version 1 / opcode set v0):
  无 header, bytecode 从 offset 0 开始。
  跳转地址相对于文件起始 (offset 0), 即直接为文件内字节位置。

跳转地址识别 (v0 opcode set):
  0x09 CI  JUMP_IF      → arg[1] = 跳转地址
  0x0a I   JUMP         → arg[0] = 跳转地址
  0x0e CGI LABEL        → arg[2] = 跳转地址
  0x12 CI  INTERRUPT_IF → arg[1] = 跳转地址

用法:
  python ai5winv1_mes_inject.py <input.mes> <trans.json> [output.mes]
  python ai5winv1_mes_inject.py <mes_dir>   <json_dir>   [output_dir]  (批量)
  --encoding <cp932|gbk>  指定输出编码 (默认 cp932)
"""
import struct, json, sys, os

# ── 编码 ──
SPECIAL_CHAR_MAP = {
    '♡': b'\xFE\x50',
    '♪': b'\xFE\x51',
    '・': b'\xFE\x52',
}

# 引擎特殊符号 (0xEBA1-EBAF, 非标准 cp932)
SPECIAL_DECODE = {
    b'\xeb\xa1': '!1', b'\xeb\xa2': '!2', b'\xeb\xa3': '!3',
    b'\xeb\xa4': '!4', b'\xeb\xa5': '!5', b'\xeb\xa6': '!6',
    b'\xeb\xa7': '!7', b'\xeb\xa8': '!?', b'\xeb\xa9': '!!',
    b'\xeb\xaa': '!a', b'\xeb\xab': '!b', b'\xeb\xac': '!c',
    b'\xeb\xad': '!d', b'\xeb\xae': '!e', b'\xeb\xaf': '!f',
}

def decode_text(raw):
    """解码引擎文本: 先替换特殊符号, 再 cp932 解码"""
    buf = bytes(raw)
    for k, v in SPECIAL_DECODE.items():
        buf = buf.replace(k, v.encode('ascii'))
    return buf.decode('cp932')

# 反向特殊符号映射 (decode_text 的逆操作)
SPECIAL_ENCODE = {v: k for k, v in SPECIAL_DECODE.items()}

def encode_text(s, encoding='cp932'):
    """将 Unicode 文本编码为游戏引擎可用的字节序列。"""
    # 先还原引擎特殊符号 (!? → 0xEBA8 等)
    for text_repr, raw_bytes in SPECIAL_ENCODE.items():
        s = s.replace(text_repr, '\x00SPEC' + raw_bytes.hex() + '\x00')

    fallback = 'gbk' if encoding == 'cp932' else 'cp932'
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\x00' and s[i+1:i+5] == 'SPEC':
            # 还原特殊符号字节
            hex_str = s[i+5:i+9]
            out += bytes.fromhex(hex_str)
            i += 10  # \x00 SPEC xxxx \x00
            continue
        c = s[i]
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
        i += 1
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

# ── Opcode 表 (v0 set) ──
CMD_ARGS = {
    0x00: '',       0x01: 'S',      0x02: 'C',      0x03: 'BCG',
    0x04: 'BCG',    0x05: 'CCG',    0x06: 'CBCG',   0x07: 'CBCG',
    0x08: 'CBCG',   0x09: 'CI',     0x0a: 'I',      0x0b: 'C',
    0x0c: '',       0x0d: '',       0x0e: 'CGI',    0x0f: 'CG',
    0x10: '',       0x11: 'V',      0x12: 'CI',     0x13: '',
    0x14: 'CG',     0x15: '',       0x16: 'BCG',    0x51: 'H',
}

JUMP_OPS = {0x09: 1, 0x0a: 0, 0x0e: 2, 0x12: 1}

# ── Struct/Var/Group 跳过 ──
def _skip_struct(dec, pos):
    while pos < len(dec):
        sb = dec[pos]; pos += 1
        if sb == 0xFF: return pos
        elif 0x80 <= sb <= 0xBF: pos += 1
        elif 0xE0 <= sb <= 0xF0: pass
        elif sb == 0xF1: pos += 2
        elif sb == 0xF2: pos += 4
        elif sb == 0xF3: pos += 2
        elif sb == 0xF4: pass
        elif 0xF5 <= sb <= 0xF8: pos += 1
    return pos

def _skip_var(dec, pos):
    while pos < len(dec):
        d = dec[pos]; pos += 1
        if d == 0: return pos
        elif d == 1:
            end = dec.find(b'\x00', pos)
            pos = end + 1 if end >= 0 else len(dec)
        elif d == 2: pos = _skip_struct(dec, pos)
    return pos

def _skip_group(dec, pos):
    while pos < len(dec):
        flag = dec[pos]; pos += 1
        if flag == 0: return pos
        pos = _skip_struct(dec, pos)
    return pos

# ── 跳转地址收集 ──
def find_jump_addrs(dec):
    """遍历字节码, 收集所有跳转地址的 (file_pos, value)。
    v1 无 header, 所有地址均为绝对偏移。
    """
    addrs = []
    pos = 0
    while pos < len(dec):
        op = dec[pos]
        if op not in CMD_ARGS:
            pos += 1; continue
        fmt = CMD_ARGS[op]
        pos += 1
        arg_idx = 0
        for ch in fmt:
            if ch == 'I':
                val = struct.unpack_from('<I', dec, pos)[0]
                if op in JUMP_OPS and JUMP_OPS[op] == arg_idx:
                    addrs.append((pos, val))
                pos += 4; arg_idx += 1
            elif ch == 'H': pos += 2; arg_idx += 1
            elif ch == 'B': pos += 1; arg_idx += 1
            elif ch == 'S':
                end = dec.find(b'\x00', pos)
                if end < 0: pos = len(dec); break
                pos = end + 1; arg_idx += 1
            elif ch == 'C': pos = _skip_struct(dec, pos); arg_idx += 1
            elif ch == 'V': pos = _skip_var(dec, pos); arg_idx += 1
            elif ch == 'G': pos = _skip_group(dec, pos); arg_idx += 1
            elif ch == 'F':
                if pos < len(dec) and dec[pos] != 0: break
                else: pos += 1; arg_idx += 1
    return addrs

# ── 文本位置解析 ──
def parse_texts(dec):
    """解析所有 TEXT (0x01) 中的 CJK 字符串, 返回位置和名前/台词分类。
    返回: [(text_id, name, str_start, str_end, is_name_text)]
    """
    all_texts = []  # (op_pos, str_start, str_end, raw, decoded)
    pos = 0
    while pos < len(dec):
        op = dec[pos]
        if op not in CMD_ARGS:
            pos += 1; continue
        fmt = CMD_ARGS[op]
        op_pos = pos; pos += 1
        for ch in fmt:
            if ch == 'I': pos += 4
            elif ch == 'H': pos += 2
            elif ch == 'B': pos += 1
            elif ch == 'S':
                end = dec.find(b'\x00', pos)
                if end < 0: pos = len(dec); break
                if op == 0x01:
                    raw = dec[pos:end]
                    try:
                        text = decode_text(raw)
                        if any(0x3000 <= ord(c) <= 0x9FFF for c in text):
                            all_texts.append((op_pos, pos, end, raw, text))
                    except:
                        pass
                pos = end + 1
            elif ch == 'C': pos = _skip_struct(dec, pos)
            elif ch == 'V': pos = _skip_var(dec, pos)
            elif ch == 'G': pos = _skip_group(dec, pos)
            elif ch == 'F':
                if pos < len(dec) and dec[pos] != 0: break
                else: pos += 1

    # 第一步: 分类 name vs message
    candidates = []  # (str_start, str_end, text, is_name, name_str)
    current_name = ''

    for op_pos, str_start, str_end, raw, text in all_texts:
        if text.startswith('【') and '】' in text:
            current_name = text[1:text.index('】')]
            candidates.append((str_start, str_end, text, True, current_name))
        else:
            candidates.append((str_start, str_end, text, False, current_name))

    # 第二步: 过滤逐字打字特效 (连续 ≥3 条相同短文本)
    filtered = []
    i = 0
    while i < len(candidates):
        ss, se, text, is_name, name = candidates[i]
        stripped = text.strip()
        if not is_name and len(stripped) <= 2:
            j = i + 1
            while j < len(candidates) and not candidates[j][3] and candidates[j][2].strip() == stripped:
                j += 1
            if j - i >= 3:
                i = j
                continue
        filtered.append(candidates[i])
        i += 1

    # 第三步: 生成结果 (跳过单字 CJK)
    result = []
    text_id = 0
    for ss, se, text, is_name, name in filtered:
        if is_name:
            result.append((None, name, ss, se, True))
            continue
        stripped = text.strip()
        cjk_only = [c for c in stripped if 0x3000 <= ord(c) <= 0x9FFF]
        if len(cjk_only) <= 1 and len(stripped) <= 2:
            continue
        result.append((text_id, name, ss, se, False))
        text_id += 1

    return result

# ── 注入 ──
def inject_file(mes_path, json_path, out_path, encoding='cp932'):
    compressed = open(mes_path, 'rb').read()
    dec = bytearray(lzss_decompress(compressed))

    with open(json_path, 'r', encoding='utf-8') as f:
        trans = json.load(f)
    td = {e['id']: e for e in trans}

    texts = parse_texts(dec)

    # 构建替换列表: (start, end, new_bytes)
    replacements = []
    replaced_count = 0

    for text_id, name_str, str_start, str_end, is_name in texts:
        if is_name:
            # 查找是否有翻译条目修改了此名前
            # 名前替换: 找到引用此 name 的第一个翻译条目
            # (简化: 遍历 td 找 name 变更)
            continue

        if text_id not in td:
            continue

        e = td[text_id]
        new_msg = e.get('message', '')
        new_name = e.get('name', '')

        # 台词替换
        if new_msg:
            old_msg = decode_text(dec[str_start:str_end])
            if old_msg != new_msg:
                new_mb = encode_text(new_msg, encoding)
                replacements.append((str_start, str_end, new_mb))
                replaced_count += 1

    # 名前替换: 收集需要修改的名前 TEXT
    name_replacements = {}  # old_name -> new_name
    for e in trans:
        new_name = e.get('name', '')
        # 通过 id 找到对应的原始名前
        for text_id, name_str, str_start, str_end, is_name in texts:
            if not is_name and text_id == e['id'] and new_name and new_name != name_str:
                name_replacements[name_str] = new_name

    for text_id, name_str, str_start, str_end, is_name in texts:
        if is_name and name_str in name_replacements:
            new_full = '【' + name_replacements[name_str] + '】'
            new_nb = encode_text(new_full, encoding)
            replacements.append((str_start, str_end, new_nb))

    replacements.sort(key=lambda x: x[0])

    # 去重 (同一位置只保留第一个替换)
    deduped = []
    for r in replacements:
        if not deduped or r[0] != deduped[-1][0]:
            deduped.append(r)
    replacements = deduped

    if not replacements:
        open(out_path, 'wb').write(compressed)
        print(f"  {os.path.basename(mes_path)}: 无修改")
        return

    # 收集跳转地址 (使用原始 bytecode)
    jump_addrs = find_jump_addrs(bytes(dec))

    # v1 无 header, 整个文件就是 bytecode
    # 重建 bytecode, 累积 delta
    new_bc = bytearray()
    delta = 0
    prev_end = 0
    breakpoints = []  # (old_abs_threshold, cumul_delta)

    for (rstart, rend, new_bytes) in replacements:
        new_bc += dec[prev_end:rstart]
        size_diff = len(new_bytes) - (rend - rstart)
        delta += size_diff
        breakpoints.append((rend, delta))
        new_bc += new_bytes
        prev_end = rend
    new_bc += dec[prev_end:]

    def remap_addr(old_addr):
        """将旧的绝对地址映射到新的绝对地址"""
        d = 0
        for (threshold, cumul_delta) in breakpoints:
            if old_addr >= threshold:
                d = cumul_delta
            else:
                break
        return old_addr + d

    # 精确修正跳转地址
    fixed = 0
    for (old_file_pos, old_val) in jump_addrs:
        new_val = remap_addr(old_val)
        if new_val == old_val:
            continue
        # 计算这个地址在新 bytecode 中的位置
        d = 0
        for (threshold, cumul_delta) in breakpoints:
            if old_file_pos >= threshold:
                d = cumul_delta
            else:
                break
        new_pos = old_file_pos + d
        if 0 <= new_pos <= len(new_bc) - 4:
            cur = struct.unpack_from('<I', new_bc, new_pos)[0]
            if cur == old_val:
                struct.pack_into('<I', new_bc, new_pos, new_val)
                fixed += 1

    # 输出
    result = lzss_compress_fake(bytes(new_bc))
    with open(out_path, 'wb') as f:
        f.write(result)

    d = len(result) - len(compressed)
    fn = os.path.basename(mes_path)
    print(f"  {fn}: {replaced_count} texts, {fixed} jumps fixed, "
          f"{len(compressed)}->{len(result)} ({'+' if d >= 0 else ''}{d})")

def main():
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
