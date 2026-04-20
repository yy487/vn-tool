#!/usr/bin/env python3
"""AI5WIN v4 MES 文本提取工具
适配 GalTransl JSON: {id, name, message}

MES 格式 (version 2, 从 AI5WINV4.exe 逆向):
  外层: LZSS 压缩 (4KB window, 0xFEE 初始写指针)
  内层:
    [0x00-0x03]  uint32  message_count
    [0x04-...]   uint32[message_count]  msg_offsets (相对 bytecode 区起始)
    [bytecode...]

  MESSAGE block:
    0x17 [u32 msg_index]       ← MESSAGE opcode
    0x01 [name_string\x00]     ← TEXT: 名前 (通常 ［xxx］ 格式)
    0x13 [u8]                  ← NEW_LINE
    0x01 [dialogue\x00]        ← TEXT: 台词
    0x0D ...                   ← SYS 等控制指令 (非文本区)

用法:
  python ai5winv4_mes_extract.py <input.mes> [output.json]
  python ai5winv4_mes_extract.py <mes_dir>   [json_dir]  (批量)
"""
import struct, json, sys, os

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

# ── 提取 ──
def extract_file(mes_path, json_path):
    compressed = open(mes_path, 'rb').read()
    dec = lzss_decompress(compressed)
    mc = struct.unpack_from('<I', dec, 0)[0]
    hs = 4 + mc * 4

    entries = []
    for mi in range(mc):
        rel = struct.unpack_from('<I', dec, 4 + mi * 4)[0]
        abs_pos = rel + hs

        # 每个 message block 必须以 0x17 MESSAGE 开头
        if abs_pos >= len(dec) or dec[abs_pos] != 0x17:
            continue

        pos = abs_pos + 5  # 跳过 0x17 + u32

        # 确定 block 结束位置
        if mi + 1 < mc:
            next_rel = struct.unpack_from('<I', dec, 4 + (mi + 1) * 4)[0]
            block_end = next_rel + hs
        else:
            block_end = len(dec)

        # 收集 TEXT 和 NEW_LINE 直到遇到非文本 opcode
        name = ''
        msg_parts = []
        first_text = True

        while pos < block_end:
            op = dec[pos]
            if op == 0x01:  # TEXT
                str_end = dec.find(b'\x00', pos + 1)
                if str_end < 0:
                    break
                raw = dec[pos + 1:str_end]
                try:
                    text = raw.decode('cp932')
                except:
                    pos = str_end + 1
                    continue

                if first_text:
                    first_text = False
                    # 检查是否含名前括号 ［xxx］ 或 【xxx】
                    if text.startswith('［') and '］' in text:
                        idx = text.index('］') + 1
                        name = text[1:idx - 1]
                        remainder = text[idx:]
                        if remainder:
                            msg_parts.append(remainder)
                    elif text.startswith('【') and '】' in text:
                        idx = text.index('】') + 1
                        name = text[1:idx - 1]
                        remainder = text[idx:]
                        if remainder:
                            msg_parts.append(remainder)
                    else:
                        msg_parts.append(text)
                else:
                    msg_parts.append(text)

                pos = str_end + 1
            elif op == 0x13:  # NEW_LINE
                pos += 2
            else:
                break  # 非文本 opcode，结束

        message = ''.join(msg_parts)
        if message:
            entries.append({"id": mi, "name": name, "message": message})

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
        files = sorted(f for f in os.listdir(src) if f.upper().endswith('.MES') and not f.startswith('_'))
        total = 0
        for fn in files:
            jp = os.path.join(out, os.path.splitext(fn)[0] + '.json')
            total += extract_file(os.path.join(src, fn), jp)
        print(f"[完成] {len(files)} 文件, {total} 条文本")
    else:
        jp = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + '.json'
        extract_file(src, jp)

if __name__ == '__main__':
    main()
