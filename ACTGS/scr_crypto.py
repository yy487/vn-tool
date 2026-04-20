#!/usr/bin/env python3
"""
ACTGS 引擎 - 加解密与档案处理核心模块
被 scr_extract.py 和 scr_inject.py 共用

提供:
  - auto_find_key(exe_path)                    从 ACTGS.exe 自动搜索 XOR 密钥
  - xor_cycle(data, key)                       循环 XOR (索引从 1 开始)
  - decrypt_script(raw, key) / encrypt_script  单个脚本的加解密 (首字节 0x58<->0x4E)
  - parse_archive(arc_path, key)               解析 arc.scr, 返回 (scripts, header, header_encrypted)
  - build_archive(header, scripts_data, key, header_encrypted)   重建 arc.scr

密钥搜索原理:
  脚本解密函数中有特征指令序列:
    83 F8 58        cmp eax, 0x58      ; 首字节 == 'X' ?
    75 xx           jnz skip
    C7 45 xx ADDR   mov [ebp-xx], ADDR ; ADDR → .data 段密钥地址
"""

import struct


# ============================================================
# PE 解析
# ============================================================
def parse_pe_sections(data):
    """解析 PE 节表, 返回 (image_base, [(name, va, rawsize, rawoff), ...])"""
    pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
    coff = data[pe_off+4 : pe_off+4+20]
    num_sec = struct.unpack('<H', coff[2:4])[0]
    opt_size = struct.unpack('<H', coff[16:18])[0]
    opt_hdr = data[pe_off+4+20 : pe_off+4+20+opt_size]
    image_base = struct.unpack('<I', opt_hdr[28:32])[0]

    sec_start = pe_off + 4 + 20 + opt_size
    sections = []
    for i in range(num_sec):
        sec = data[sec_start + i*40 : sec_start + (i+1)*40]
        name = sec[:8].rstrip(b'\x00').decode('ascii', 'replace')
        va      = struct.unpack('<I', sec[12:16])[0]
        rawsize = struct.unpack('<I', sec[16:20])[0]
        rawoff  = struct.unpack('<I', sec[20:24])[0]
        sections.append((name, va, rawsize, rawoff))
    return image_base, sections


def _va_to_fileoff(va_addr, image_base, sections):
    rva = va_addr - image_base
    for _, sva, srawsize, srawoff in sections:
        if sva <= rva < sva + srawsize:
            return srawoff + (rva - sva)
    return None


def auto_find_key(exe_path):
    """从 ACTGS.exe 自动搜索 XOR 密钥, 返回 bytes 或 None"""
    with open(exe_path, 'rb') as f:
        data = f.read()

    image_base, sections = parse_pe_sections(data)

    text_sec = next((s for s in sections if s[0] == '.text'), None)
    if not text_sec:
        return None

    text_start = text_sec[3]
    text_end   = text_sec[3] + text_sec[2]

    pattern = bytes([0x83, 0xF8, 0x58])  # cmp eax, 0x58
    pos = text_start

    while pos < text_end:
        pos = data.find(pattern, pos, text_end)
        if pos < 0:
            break

        # 在后续 25 字节内搜索 C7 45 xx [dword] (mov [ebp-xx], imm32)
        window = data[pos : pos + 30]
        for j in range(3, 25):
            if j + 6 < len(window) and window[j] == 0xC7 and window[j+1] == 0x45:
                addr = struct.unpack('<I', window[j+3 : j+7])[0]
                foff = _va_to_fileoff(addr, image_base, sections)
                if foff and foff < len(data):
                    end_idx = data.index(0, foff) if 0 in data[foff:foff+64] else foff
                    key = data[foff : end_idx]
                    if 4 <= len(key) <= 32:
                        return key
        pos += 1

    return None


# ============================================================
# XOR 加解密
# ============================================================
def xor_cycle(data, key):
    """循环 XOR: ki = ki % klen + 1, 索引从 1 开始 (与引擎一致)"""
    out = bytearray(data)
    klen = len(key)
    ki = 0
    for i in range(len(out)):
        out[i] ^= key[ki % klen]
        ki = ki % klen + 1
    return bytes(out)


def decrypt_script(raw, key):
    """脚本解密: 首字节 0x58('X') → 0x4E('N'), 其余循环 XOR"""
    if not raw or raw[0] != 0x58:
        return raw
    dec = bytearray(raw)
    klen = len(key)
    ki = 0
    for j in range(1, len(dec)):
        dec[j] ^= key[ki % klen]
        ki = ki % klen + 1
    dec[0] = 0x4E
    return bytes(dec)


def encrypt_script(dec_data, key):
    """脚本加密: 首字节 → 0x58, 其余循环 XOR"""
    if not dec_data:
        return dec_data
    enc = bytearray(dec_data)
    enc[0] = 0x58
    klen = len(key)
    ki = 0
    for j in range(1, len(enc)):
        enc[j] ^= key[ki % klen]
        ki = ki % klen + 1
    return bytes(enc)


# ============================================================
# 档案解析 / 重建
# ============================================================
_HDR_SIZE   = 0x10
_ENTRY_SIZE = 0x20
_MAX_FILES  = 100000


def parse_archive(arc_path, key):
    """
    解析 arc.scr
    返回 (scripts, header, header_encrypted)
      scripts: [(name, decrypted_bytes), ...]
      header: 原始头部 16 字节 (未加密形式, 用于 build_archive 复用)
      header_encrypted: 原档案头部是否加密 (重建时需保持一致)
    """
    with open(arc_path, 'rb') as f:
        data = f.read()

    header_encrypted = False
    header_raw = bytearray(data[:_HDR_SIZE])

    file_count = struct.unpack('<I', data[:4])[0]

    if file_count == 0 or file_count > _MAX_FILES or _HDR_SIZE + file_count * _ENTRY_SIZE > len(data):
        # 头部可能被加密
        header_raw = bytearray(xor_cycle(data[:_HDR_SIZE], key))
        file_count = struct.unpack('<I', header_raw[:4])[0]
        if file_count == 0 or file_count > _MAX_FILES or _HDR_SIZE + file_count * _ENTRY_SIZE > len(data):
            raise ValueError(f"无法解析档案: 文件数={file_count} 不合理")
        header_encrypted = True

    index_enc = data[_HDR_SIZE : _HDR_SIZE + file_count * _ENTRY_SIZE]
    index_dec = bytearray(xor_cycle(index_enc, key))

    first_name = index_dec[8:_ENTRY_SIZE].split(b'\x00')[0]
    if not first_name or not all(32 <= b < 127 for b in first_name):
        raise ValueError(f"索引解密失败: 首条目文件名非法 ({first_name.hex()})")

    scripts = []
    for i in range(file_count):
        entry = index_dec[i * _ENTRY_SIZE : (i + 1) * _ENTRY_SIZE]
        offset = struct.unpack('<I', entry[0:4])[0]
        size   = struct.unpack('<I', entry[4:8])[0]
        name   = entry[8:_ENTRY_SIZE].split(b'\x00')[0].decode('ascii')
        scr    = decrypt_script(data[offset : offset + size], key)
        scripts.append((name, scr))

    return scripts, bytes(header_raw), header_encrypted


def build_archive(header, scripts_data, key, header_encrypted=False):
    """
    重建 arc.scr
      header: parse_archive 返回的未加密头部
      scripts_data: [(name, already_encrypted_bytes), ...]
    """
    file_count = len(scripts_data)
    data_start = _HDR_SIZE + file_count * _ENTRY_SIZE
    index_entries = bytearray()
    file_data = bytearray()
    current_offset = data_start

    for name, enc_scr in scripts_data:
        entry = bytearray(_ENTRY_SIZE)
        struct.pack_into('<I', entry, 0, current_offset)
        struct.pack_into('<I', entry, 4, len(enc_scr))
        name_bytes = name.encode('ascii')
        entry[8:8+len(name_bytes)] = name_bytes
        index_entries.extend(entry)
        file_data.extend(enc_scr)
        current_offset += len(enc_scr)

    index_enc = xor_cycle(bytes(index_entries), key)

    out = bytearray(header)
    struct.pack_into('<I', out, 0, file_count)
    if header_encrypted:
        out = bytearray(xor_cycle(bytes(out), key))

    out.extend(index_enc)
    out.extend(file_data)
    return bytes(out)


# ============================================================
# CLI 便捷入口: 直接运行可仅提取密钥
# ============================================================
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <ACTGS.exe>")
        print(f"  从 EXE 中搜索并打印 XOR 密钥")
        sys.exit(1)
    key = auto_find_key(sys.argv[1])
    if not key:
        print("错误: 未找到密钥")
        sys.exit(1)
    print(f"密钥 (hex): {key.hex()}")
    print(f"密钥 (raw): {key!r}")
    print(f"长度: {len(key)}")
