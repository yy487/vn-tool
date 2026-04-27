#!/usr/bin/env python3
"""
AI5WIN (Line2) Engine MES Script Text Injector
================================================
用法: python mes_inject.py <original.mes> <translated.json> [output.mes]
      python mes_inject.py <mes_dir> <json_dir> <output_dir>  (batch mode)

基于AI5WINScript command_library v2完整opcode格式定义精确解析字节码。
"""

import struct
import json
import sys
import os


# ═══════════════════════════════════════════════════════════════════
#  LZSS
# ═══════════════════════════════════════════════════════════════════

def lzss_decompress(src: bytes) -> bytes:
    window = bytearray(0x1000)
    win_pos = 0xFEE
    output = bytearray()
    src_pos = 0
    comp_size = len(src)
    flags = 0; flag_bits = 0
    while src_pos < comp_size:
        if flag_bits == 0:
            flags = src[src_pos]; src_pos += 1; flag_bits = 8
        if flags & 1:
            if src_pos >= comp_size: break
            b = src[src_pos]; src_pos += 1
            output.append(b); window[win_pos] = b; win_pos = (win_pos+1)&0xFFF
        else:
            if src_pos+1 >= comp_size: break
            low = src[src_pos]; high = src[src_pos+1]; src_pos += 2
            off = low | ((high&0xF0)<<4); length = (high&0x0F)+3
            for k in range(length):
                b = window[(off+k)&0xFFF]
                output.append(b); window[win_pos] = b; win_pos = (win_pos+1)&0xFFF
        flags >>= 1; flag_bits -= 1
    return bytes(output)


def lzss_compress(src: bytes) -> bytes:
    """纯literal模式, 保证与游戏解压器100%兼容"""
    output = bytearray()
    for i in range(0, len(src), 8):
        output.append(0xFF)
        for j in range(8):
            if i + j < len(src):
                output.append(src[i + j])
    return bytes(output)


# ═══════════════════════════════════════════════════════════════════
#  AI5WIN v2 opcode 格式定义
# ═══════════════════════════════════════════════════════════════════
#
# C = 表达式 (struct_library操作码流, 0xFF终止)
# I = uint32    H = uint16    B = uint8
# S = CP932 string + \0
# V = {01+S | 02+C}* 00       G = {01+C}* 00
# F = 读1字节, 非0则停止解析后续参数

OPCODES_V2 = {
    0x00: '',       # RETURN
    0x01: 'S',      # TEXT
    0x02: 'S',      # SYSTEM_TEXT
    0x03: 'HCG',    # B_FLAG_SET
    0x04: 'BCG',    # W_FLAG_SET
    0x05: 'CCG',    # EXT_B_FLAG_SET
    0x06: 'CBCG',   # PC_FLAG_SET
    0x07: 'CBCG',   # A_FLAG_SET
    0x08: 'CFCG',   # G_FLAG_SET
    0x09: 'CBCG',   # PW_FLAG_SET
    0x0A: 'CBCG',   # PB_FLAG_SET
    0x0B: 'CI',     # JUMP_IF
    0x0C: 'I',      # JUMP
    0x0D: 'CV',     # SYS
    0x0E: 'V',      # CH_POS
    0x0F: 'V',      # CALL
    0x10: 'VI',     # MENU_SET
    0x11: 'V',      # INTERRUPT
    0x12: 'V',      # SPEC_SYS
    0x13: 'B',      # NEW_LINE
    0x14: 'CI',     # INTERRUPT_IF
    0x15: 'CG',     # MENU
    0x16: 'BCG',    # FLAG_D_SET
    0x17: 'I',      # MESSAGE (msg number, NOT address)
    0x18: '',       # (no args)
    0x1B: 'CG',     # (unnamed)
    0x1C: 'CI',     # (unnamed)
    0x1D: 'CG',     # (unnamed)
    0x1F: 'I',      # LABEL (label id, NOT address)
}

# opcode → 哪个参数索引(0-based)是地址
ADDR_PARAMS = {0x0B: 1, 0x0C: 0, 0x10: 1, 0x14: 1, 0x1C: 1}

# NOT addresses (uint32 but not jump targets):
NOT_ADDR = {0x17, 0x1F}


# ═══════════════════════════════════════════════════════════════════
#  参数解析
# ═══════════════════════════════════════════════════════════════════

def _skip_C(data, pos):
    """跳过C类型表达式(0xFF终止)"""
    while pos < len(data):
        b = data[pos]; pos += 1
        if b == 0xFF: return pos
        if b < 0x80: continue
        if b in (0x80, 0xA0, 0xC0, 0xF5, 0xF6, 0xF7, 0xF8): pos += 1
        elif 0xE0 <= b <= 0xF0: continue
        elif b == 0xF1: pos += 2
        elif b == 0xF2: pos += 4
        elif b == 0xF3: pos += 2
        elif b == 0xF4: continue
        elif b == 0xF9: pos += 1
    return pos


def _skip_V(data, pos):
    """跳过V类型: {01+S | 02+C}* 00"""
    while pos < len(data):
        tag = data[pos]
        if tag == 0x00: return pos + 1
        elif tag == 0x01:
            pos += 1
            while pos < len(data) and data[pos] != 0x00: pos += 1
            if pos < len(data): pos += 1
        elif tag == 0x02:
            pos += 1; pos = _skip_C(data, pos)
        else:
            pos += 1
    return pos


def _skip_G(data, pos):
    """跳过G类型: {01+C}* 00"""
    while pos < len(data):
        tag = data[pos]
        if tag == 0x00: return pos + 1
        elif tag == 0x01:
            pos += 1; pos = _skip_C(data, pos)
        else:
            return pos + 1
    return pos


def _skip_S(data, pos):
    """跳过S类型: null-terminated string"""
    while pos < len(data) and data[pos] != 0x00: pos += 1
    if pos < len(data): pos += 1
    return pos


def _parse_args(data, pos, fmt):
    """按格式字符串解析参数, 返回 (new_pos, {param_index: offset_of_I_param})"""
    i_positions = {}
    param_idx = 0
    fi = 0
    while fi < len(fmt) and pos < len(data):
        c = fmt[fi]; fi += 1
        if c == 'C':
            pos = _skip_C(data, pos)
        elif c == 'I':
            i_positions[param_idx] = pos
            pos += 4
        elif c == 'H':
            pos += 2
        elif c == 'B':
            pos += 1
        elif c == 'S':
            pos = _skip_S(data, pos)
        elif c == 'V':
            pos = _skip_V(data, pos)
        elif c == 'G':
            pos = _skip_G(data, pos)
        elif c == 'F':
            if pos < len(data) and data[pos] != 0:
                break  # 非0 → 停止, 不消费
            pos += 1  # 消费0, 继续
        param_idx += 1
    return pos, i_positions


# ═══════════════════════════════════════════════════════════════════
#  字节码扫描
# ═══════════════════════════════════════════════════════════════════

def _scan_segment(decomp, start, end, visited):
    """扫描一个字节码段, 收集地址引用"""
    ptrs = []
    fs = len(decomp)
    pos = start
    while pos < end and pos < fs:
        if pos in visited: break
        visited.add(pos)
        op = decomp[pos]; pos += 1

        if op in OPCODES_V2:
            fmt = OPCODES_V2[op]
            if not fmt:
                continue
            new_pos, i_positions = _parse_args(decomp, pos, fmt)
            if op in ADDR_PARAMS:
                target_idx = ADDR_PARAMS[op]
                if target_idx in i_positions:
                    addr_pos = i_positions[target_idx]
                    if addr_pos + 4 <= fs:
                        val = struct.unpack_from('<I', decomp, addr_pos)[0]
                        ptrs.append((addr_pos, val))
            pos = new_pos
        else:
            # 未知opcode → 跳过 {C}* 00 (best effort)
            while pos < fs and decomp[pos] != 0x00:
                pos = _skip_C(decomp, pos)
            if pos < fs: pos += 1
    return ptrs


def find_all_offsets(decomp):
    """收集所有uint32地址引用。
    
    AI5WIN v2: 所有地址都是相对偏移(相对于header末尾)。
    true_address = stored_value + header_size
    
    头部结构:
      [0x00] uint32 msg_count
      [0x04] uint32[msg_count] msg_offsets  ← 相对偏移
      [header_end...] 字节码               ← 内含相对偏移的跳转地址
    
    返回: [(file_pos, stored_value, header_size), ...]
    """
    fs = len(decomp)
    if fs < 8: return []

    # === 解析头部 ===
    msg_count = struct.unpack_from('<I', decomp, 0)[0]
    header_size = 4 + msg_count * 4
    
    if header_size >= fs or msg_count > 10000:
        header_size = 0
        msg_count = 0

    all_ptrs = []
    entry_points = []  # 绝对地址, 用于段扫描

    # 消息偏移表 (全部是相对偏移)
    if msg_count > 0:
        for i in range(msg_count):
            off = 4 + i * 4
            val = struct.unpack_from('<I', decomp, off)[0]
            true_addr = val + header_size
            if 0 < true_addr < fs:
                all_ptrs.append((off, val, header_size))
                entry_points.append(true_addr)

    # 字节码从 header_size 开始 (此引擎无额外跳转表)
    table_end = header_size

    if not entry_points:
        entry_points = [header_size]

    # === 字节码段扫描 ===
    all_starts = sorted(set([table_end] + entry_points))
    visited = set()
    for i, ep in enumerate(all_starts):
        seg_end = all_starts[i+1] if i+1 < len(all_starts) else fs
        for addr_pos, val in _scan_segment(decomp, ep, seg_end, visited):
            # 字节码中的跳转地址也是相对偏移!
            all_ptrs.append((addr_pos, val, header_size))

    last = all_starts[-1]
    if last < fs:
        for addr_pos, val in _scan_segment(decomp, last, fs, visited):
            all_ptrs.append((addr_pos, val, header_size))

    # 过滤
    return [(o, v, b) for o, v, b in all_ptrs if 0 < v + b < fs]


# ═══════════════════════════════════════════════════════════════════
#  注入
# ═══════════════════════════════════════════════════════════════════

def inject_text(decomp, replacements):
    if not replacements: return decomp
    replacements.sort(key=lambda x: x[0])
    known_ptrs = find_all_offsets(decomp)

    result = bytearray()
    prev_end = 0
    breakpoints = []
    for orig_off, old_bytes, new_bytes in replacements:
        result.extend(decomp[prev_end:orig_off])
        result.extend(new_bytes)
        prev_end = orig_off + len(old_bytes)
        delta = len(new_bytes) - len(old_bytes)
        cum = (breakpoints[-1][1] if breakpoints else 0) + delta
        breakpoints.append((orig_off, cum))
    result.extend(decomp[prev_end:])

    if not breakpoints: return decomp

    def adjust_absolute(abs_val):
        """根据绝对地址计算偏移"""
        s = 0
        for t, c in breakpoints:
            if abs_val > t: s = c
            else: break
        return s

    for pp, pv, base in known_ptrs:
        # pp = 文件中的位置, pv = 存储的值, base = 偏移基准
        # 真实绝对地址 = pv + base
        abs_addr = pv + base
        
        # pp 的新位置
        new_pp = pp + adjust_absolute(pp)
        # 绝对地址的偏移量
        addr_shift = adjust_absolute(abs_addr)
        # 新的存储值 = (abs_addr + shift) - base = pv + shift
        new_pv = pv + addr_shift
        
        struct.pack_into('<I', result, new_pp, new_pv)

    return bytes(result)


# ═══════════════════════════════════════════════════════════════════
#  文本处理
# ═══════════════════════════════════════════════════════════════════

def process_one(mes_path, json_path, out_path):
    with open(mes_path, 'rb') as f: raw = f.read()
    decomp = lzss_decompress(raw)
    with open(json_path, 'r', encoding='utf-8') as f: entries = json.load(f)

    orig_map = {}
    i = 0
    while i < len(decomp) - 2:
        if decomp[i] == 0x01:
            j = i + 1; valid = True
            while j < len(decomp):
                c = decomp[j]
                if c == 0x00: break
                if (0x81 <= c <= 0x9F) or (0xE0 <= c <= 0xEF):
                    if j+1 < len(decomp) and ((0x40 <= decomp[j+1] <= 0x7E) or (0x80 <= decomp[j+1] <= 0xFC)):
                        j += 2; continue
                    else: valid = False; break
                elif 0x20 <= c <= 0x7E: j += 1
                elif c == 0x0A: j += 1
                else: valid = False; break
            if valid and j < len(decomp) and decomp[j] == 0x00 and j > i+1:
                raw_str = decomp[i+1:j]
                sc = 0; k = 0
                while k < len(raw_str)-1:
                    if ((0x81 <= raw_str[k] <= 0x9F) or (0xE0 <= raw_str[k] <= 0xEF)) and \
                       ((0x40 <= raw_str[k+1] <= 0x7E) or (0x80 <= raw_str[k+1] <= 0xFC)):
                        sc += 1; k += 2
                    else: k += 1
                text = raw_str.decode('cp932', errors='replace')
                is_file = any(text.lower().endswith(ext) for ext in ['.gcc','.ogg','.mes','.wav'])
                if sc >= 2 and not is_file:
                    orig_map[i+1] = text
                i = j + 1; continue
        i += 1

    replacements = []
    replaced = 0
    for entry in entries:
        offset = entry['offset']
        new_text = entry.get('message_cn') or entry.get('translated') or entry.get('message', '')
        if not new_text: continue
        orig_text = orig_map.get(offset)
        if orig_text is None: continue
        if new_text == orig_text: continue
        orig_bytes = orig_text.encode('cp932', errors='replace')
        new_bytes = new_text.encode('cp932', errors='replace')
        replacements.append((offset, orig_bytes, new_bytes))
        replaced += 1

    if replaced == 0:
        with open(out_path, 'wb') as f: f.write(raw)
        print(f"  {os.path.basename(mes_path)}: 0/{len(entries)} replaced (copied)")
        return 0

    new_decomp = inject_text(decomp, replacements)
    compressed = lzss_compress(new_decomp)
    with open(out_path, 'wb') as f: f.write(compressed)
    print(f"  {os.path.basename(mes_path)}: {replaced}/{len(entries)} replaced, {len(raw)}->{len(compressed)} bytes")
    return replaced


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <original.mes> <translated.json> [output.mes]")
        print(f"       {sys.argv[0]} <mes_dir> <json_dir> <output_dir>  (batch mode)")
        sys.exit(1)

    src = sys.argv[1]
    json_src = sys.argv[2]

    if os.path.isdir(src) and os.path.isdir(json_src):
        if len(sys.argv) < 4:
            print("Error: batch mode requires output_dir"); sys.exit(1)
        out_dir = sys.argv[3]
        os.makedirs(out_dir, exist_ok=True)

        all_files = sorted(f for f in os.listdir(src) if os.path.isfile(os.path.join(src, f)))
        total_files = 0; total_replaced = 0
        for fn in all_files:
            if fn.startswith('_'):
                with open(os.path.join(src, fn), 'rb') as fi, open(os.path.join(out_dir, fn), 'wb') as fo:
                    fo.write(fi.read())
                continue
            mes_path = os.path.join(src, fn)
            out_path = os.path.join(out_dir, fn)
            if not fn.upper().endswith('.MES'):
                with open(mes_path, 'rb') as fi, open(out_path, 'wb') as fo: fo.write(fi.read())
                continue
            json_path = os.path.join(json_src, os.path.splitext(fn)[0] + '.json')
            if not os.path.exists(json_path):
                with open(mes_path, 'rb') as fi, open(out_path, 'wb') as fo: fo.write(fi.read())
                continue
            try:
                n = process_one(mes_path, json_path, out_path)
                total_files += 1; total_replaced += n
            except Exception as e:
                print(f"  ✗ {fn}: {e}")

        print(f"\nDone: {total_files} files, {total_replaced} texts replaced -> {out_dir}/")
    else:
        out_path = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(src)[0] + '_patched.mes'
        process_one(src, json_src, out_path)


if __name__ == '__main__':
    main()
