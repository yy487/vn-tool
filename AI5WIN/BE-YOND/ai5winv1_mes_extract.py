#!/usr/bin/env python3
"""AI5WIN v1 MES 文本提取工具
适配 GalTransl JSON: {id, name, message}

MES 格式 (version 1 / opcode set v0, 从 AI5WINV1.exe 逆向):
  外层: LZSS 压缩 (4KB window, 0xFEE 初始写指针)
  内层: 无 header, bytecode 从 offset 0 开始
  跳转地址相对于文件起始 (offset 0), 即直接为文件内字节位置。

  对话模式:
    0x03 B_FLAG_SET         ← 设定名前相关 flag
    0x01 TEXT [【name】\x00] ← 名前 (【】 括号)
    0x11 INTERRUPT
    0x09 JUMP_IF            ← 语音条件跳转
    0x0B                    ← 条件处理
    0x02                    ← 语音控制
    0x01 TEXT [voice.wav\x00]← 语音文件名
    0x00 RETURN
    0x07 A_FLAG             ← 文本显示设定
    0x01 TEXT [dialogue\x00] ← 台词

用法:
  python ai5winv1_mes_extract.py <input.mes> [output.json]
  python ai5winv1_mes_extract.py <mes_dir>   [json_dir]  (批量)
"""
import struct, json, sys, os

# ── 特殊符号 (引擎自定义, 0xEBA1-EBAF, 非标准 cp932) ──
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

# ── Opcode 表 (v0 set — 从实际脚本验证) ──
CMD_ARGS = {
    0x00: '',       # RETURN
    0x01: 'S',      # TEXT
    0x02: 'C',      # (条件/语音控制)
    0x03: 'BCG',    # B_FLAG_SET
    0x04: 'BCG',    # W_FLAG_SET
    0x05: 'CCG',    # EXT_B_FLAG_SET
    0x06: 'CBCG',   # PC_FLAG_SET
    0x07: 'CBCG',   # A_FLAG_SET
    0x08: 'CBCG',   # (flag set)
    0x09: 'CI',     # JUMP_IF
    0x0a: 'I',      # JUMP
    0x0b: 'C',      # (条件)
    0x0c: '',       # (空)
    0x0d: '',       # (空)
    0x0e: 'CGI',    # LABEL
    0x0f: 'CG',     # CALL
    0x10: '',       # (空)
    0x11: 'V',      # INTERRUPT
    0x12: 'CI',     # INTERRUPT_IF
    0x13: '',       # NEW_LINE
    0x14: 'CG',     # (控制)
    0x15: '',       # MENU
    0x16: 'BCG',    # FLAG_D_SET
    0x51: 'H',      # (特殊)
}

# v0 跳转指令: opcode -> 第几个参数是跳转地址
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

# ── 提取 ──
def extract_file(mes_path, json_path):
    compressed = open(mes_path, 'rb').read()
    dec = lzss_decompress(compressed)

    # v1 无 header, bytecode 从 offset 0 开始
    # 收集所有 TEXT (0x01) opcode 的字符串及其位置
    all_texts = []  # (op_pos, str_start, str_end, raw_bytes)
    pos = 0
    while pos < len(dec):
        op = dec[pos]
        if op not in CMD_ARGS:
            pos += 1; continue
        fmt = CMD_ARGS[op]
        op_pos = pos
        pos += 1
        for ch in fmt:
            if ch == 'I': pos += 4
            elif ch == 'H': pos += 2
            elif ch == 'B': pos += 1
            elif ch == 'S':
                end = dec.find(b'\x00', pos)
                if end < 0: pos = len(dec); break
                if op == 0x01:
                    all_texts.append((op_pos, pos, end, dec[pos:end]))
                pos = end + 1
            elif ch == 'C': pos = _skip_struct(dec, pos)
            elif ch == 'V': pos = _skip_var(dec, pos)
            elif ch == 'G': pos = _skip_group(dec, pos)
            elif ch == 'F':
                if pos < len(dec) and dec[pos] != 0: break
                else: pos += 1

    # 配对名前+台词, 输出 GalTransl JSON
    # 第一步: 收集所有 CJK 文本候选
    candidates = []  # (str_start, str_end, text, is_name, name_str)
    current_name = ''

    for op_pos, str_start, str_end, raw in all_texts:
        try:
            text = decode_text(raw)
        except:
            continue

        # 跳过非 CJK 文本 (文件名、控制字符串)
        if not any(0x3000 <= ord(c) <= 0x9FFF for c in text):
            continue

        # 判断是否为名前 (【name】 格式)
        if text.startswith('【') and '】' in text:
            current_name = text[1:text.index('】')]
            candidates.append((str_start, str_end, text, True, current_name))
            continue

        candidates.append((str_start, str_end, text, False, current_name))

    # 第二步: 过滤逐字打字特效 (连续 ≥3 条相同短文本)
    filtered = []
    i = 0
    while i < len(candidates):
        ss, se, text, is_name, name = candidates[i]
        stripped = text.strip()
        if not is_name and len(stripped) <= 2:
            # 检查后续是否连续重复 (strip 后比较)
            j = i + 1
            while j < len(candidates) and not candidates[j][3] and candidates[j][2].strip() == stripped:
                j += 1
            if j - i >= 3:
                # 连续 ≥3 条相同短文本 = 特效, 全部跳过
                i = j
                continue
        filtered.append(candidates[i])
        i += 1

    # 第三步: 生成 JSON entries (跳过名前和单字CJK)
    entries = []
    text_id = 0
    for ss, se, text, is_name, name in filtered:
        if is_name:
            continue
        # 跳过单字 CJK (逐字打字演出, 不可翻译)
        stripped = text.strip()
        cjk_only = [c for c in stripped if 0x3000 <= ord(c) <= 0x9FFF]
        if len(cjk_only) <= 1 and len(stripped) <= 2:
            continue
        entries.append({"id": text_id, "name": name, "message": text})
        text_id += 1

    if not entries:
        print(f"  {os.path.basename(mes_path)}: 无文本, 跳过")
        return 0

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"  {os.path.basename(mes_path)}: {len(compressed)}->{len(dec)} bytes, {len(entries)} texts")
    return len(entries)

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    src = sys.argv[1]
    if os.path.isdir(src):
        out = sys.argv[2] if len(sys.argv) > 2 else src + '_json'
        os.makedirs(out, exist_ok=True)
        files = sorted(f for f in os.listdir(src)
                       if f.upper().endswith('.MES') and not f.startswith('_'))
        total = 0
        for fn in files:
            jp = os.path.join(out, os.path.splitext(fn)[0] + '.json')
            try:
                total += extract_file(os.path.join(src, fn), jp)
            except Exception as e:
                print(f"  [ERROR] {fn}: {e}")
        print(f"[完成] {len(files)} 文件, {total} 条文本")
    else:
        jp = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + '.json'
        extract_file(src, jp)

if __name__ == '__main__':
    main()
