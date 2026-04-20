#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HIMITSU ISF 脚本核心模块 (仅 MPX 0xD197 版本)
提供加解密、解析、重建三组底层函数, 供 isf_extract / isf_inject 共用。

格式备忘:
    Header:
      u32  head_len       整个头部长度 (含 offsetlist)
      u16  version        0xD197 → XOR 0xFF 加密体
      u8   key            版本参数 (本版本不用)
      u8   pad
      u32[] offsetlist    (head_len-8)/4 项, 每项指向 body 内某条指令的旧偏移
    Body:
      变长指令, 每条:
        u8  op
        u8  len_marker
             < 0x80  → total_len = marker      (head=2B)
             = 0x80  → total_len = next u8     (head=3B)
             = 0x81  → total_len = next u8+0x100 (head=3B)
        content = total_len - head_bytes 字节
    加密:
        body + offsetlist 整体 XOR 0xFF, 前 8 字节保持明文

子指令长度表 (用于 0x2b/0x2c talk content 内部扫描):
    cmd 0x01/4B 0x04/1B 0x08/4B 0x09/1B 0x0A/4B 0x0B/2B 0x0C/2B 0x10/2B 0x11/4B
    cmd 0xFF    = 文本开始, 一直到 _find_text_end 判定为止
"""
import struct
import re

# 子命令固定长度
SUB_FIXED_LEN = {
    0x01: 4, 0x04: 1, 0x08: 4, 0x09: 1, 0x0A: 4,
    0x0B: 2, 0x0C: 2, 0x10: 2, 0x11: 4,
}

# ---------- 加解密 ----------

def isf_decrypt(data: bytes) -> bytes:
    """.ISF 内容 XOR 0xFF 解密, 仅 [8:]; 前 8 字节明文"""
    b = bytearray(data)
    for i in range(8, len(b)):
        b[i] = (~b[i]) & 0xFF
    return bytes(b)

def isf_encrypt(data: bytes) -> bytes:
    """对称"""
    return isf_decrypt(data)

# ---------- 脚本解析 ----------

def parse_script(plain: bytes):
    """解析明文脚本 → (head_len, version_info, offsetlist, ops, old_off_to_idx)"""
    head_len = struct.unpack_from('<I', plain, 0)[0]
    version_info = plain[4:8]
    n_off = (head_len - 8) // 4
    offsetlist = list(struct.unpack_from(f'<{n_off}I', plain, 8))

    body = plain[head_len:]
    ops = []
    old_off_to_idx = {}
    pos = 0
    idx = 0
    while pos < len(body):
        start = pos
        old_off_to_idx[start] = idx
        op = body[pos]; pos += 1
        l = body[pos]; pos += 1
        if l < 0x80:
            total = l; head = 2
        elif l == 0x80:
            total = body[pos]; pos += 1; head = 3
        elif l == 0x81:
            total = body[pos] + 0x100; pos += 1; head = 3
        else:
            raise ValueError(f'bad len_marker 0x{l:02X} @body+0x{start:X}')
        content_len = total - head
        content = body[start+head : start+head+content_len]
        if len(content) != content_len:
            raise ValueError(f'content truncated @body+0x{start:X}')
        ops.append({'op': op, 'content': content})
        pos = start + total
        idx += 1
    old_off_to_idx[pos] = idx  # sentinel
    return head_len, version_info, offsetlist, ops, old_off_to_idx

def op_to_bytes(op: dict) -> bytes:
    content = op['content']
    l = len(content) + 2
    if l < 0x80:
        return bytes([op['op'], l]) + content
    if l + 1 < 0x100:
        return bytes([op['op'], 0x80, l + 1]) + content
    if l + 1 < 0x200:
        return bytes([op['op'], 0x81, (l + 1) - 0x100]) + content
    raise ValueError(f'op content too long: {l}')

def build_script(head_len_orig: int, version_info: bytes,
                 offsetlist: list, ops: list, old_off_to_idx: dict) -> bytes:
    """重建明文脚本; offsetlist 通过 old_off_to_idx 映射到新偏移"""
    op_new_off = {}
    body = bytearray()
    for i, op in enumerate(ops):
        op_new_off[i] = len(body)
        body += op_to_bytes(op)
    op_new_off[len(ops)] = len(body)

    new_offs = bytearray()
    for old in offsetlist:
        idx = old_off_to_idx.get(old)
        new_off = op_new_off[idx] if idx is not None else old
        new_offs += struct.pack('<I', new_off)

    out = bytearray()
    out += struct.pack('<I', head_len_orig)
    out += version_info
    out += new_offs
    pad = head_len_orig - len(out)
    if pad > 0:
        out += b'\0' * pad
    elif pad < 0:
        raise ValueError(f'head overflow: {len(out)} > {head_len_orig}')
    out += body
    return bytes(out)

# ---------- 文本边界识别 (talk content 内部) ----------

def find_text_end(content: bytes, start: int) -> int:
    """从 start 位置开始扫描文本结束位置 (参考 ikuar ISF_FILE 的 MPX 分支)

    规则:
      1) 遇到 00 06 FF → 句中换行, 整体跳过继续扫
      2) 独立 0x00 → 偷看下一字节, 若为 00/05/06/FF 则结束
      3) 末尾 0x03 → 结束
    """
    end = start
    n = len(content)
    while end < n:
        if end + 2 < n and content[end:end+3] == b'\x00\x06\xFF':
            end += 3
            continue
        if content[end] == 0x00:
            if end + 1 < n:
                nb = content[end+1]
                if nb in (0x00, 0x05, 0x06, 0xFF):
                    break
            else:
                break
        elif content[end] == 0x03 and end + 1 == n:
            break
        end += 1
    return end

def scan_talk_text(content: bytes):
    """扫描 talk content 找到 0xFF 文本段, 返回 (text_bytes_cleaned, has_name_br, tstart, tend) 或 None"""
    if len(content) == 0:
        return None
    off = 1  # content[0] 固定跳过
    while off < len(content):
        cmd = content[off]; off += 1
        if cmd in SUB_FIXED_LEN:
            off += SUB_FIXED_LEN[cmd]
        elif cmd == 0xFF:
            tstart = off
            tend = find_text_end(content, off)
            text_bytes = content[tstart:tend]
            has_name_br = b'\x81\x7A\x00\x06\xFF' in text_bytes
            cleaned = text_bytes.replace(b'\x00\x06\xFF', b'').rstrip(b'\x00')
            return (cleaned, has_name_br, tstart, tend)
        # 其他未知 cmd: 继续扫描
    return None

# ---------- SJIS 辅助 ----------

def sjis_decode(b: bytes) -> str:
    return b.decode('cp932', errors='replace')

def sjis_encode(s: str) -> bytes:
    return s.encode('cp932', errors='replace')

# ---------- HIMITSU 字符表 (EXE @0x6DC7C, 128 项, 每项 2B SJIS) ----------
# 单字节 token < 0x80 走表; 字节 >= 0x80 走 SJIS 双字节
HIMITSU_TABLE = (
    '\u3000\u3000、。・？！（）「」０１２３４５６７８９'
    'あいうえおかがきぎくぐ\u3000げこごさざしじすずせぜそぞただちぢっつづてでとど'
    'なにぬねのはばひびふぶへべほぼまみむめもゃやゅゆょよらりるれろわをん'
    'アイウエオカキクケコサシスセソタチッツテトナニけネノハヒフヘホマミムメモヤ'
)
assert len(HIMITSU_TABLE) == 128
# 反查表: char → token byte
# 全角空格 '\u3000' 对应 0x00 和 0x01 两个 token, 实际数据里 0x01 使用率远高于 0x00,
# 所以反查优先映射到 0x01
_REV = {}
for _i, _c in enumerate(HIMITSU_TABLE):
    if _c not in _REV:
        _REV[_c] = _i
_REV['\u3000'] = 0x01  # 覆盖: '\u3000' → 0x01

def decode_himitsu_text(data: bytes) -> str:
    """HIMITSU 文本字节流 → Unicode 字符串
       规则:
         byte < 0x80            → 查 HIMITSU_TABLE
         byte in [0x81-0x9F] or [0xE0-0xFC] + 合法 SJIS trail → 双字节汉字/片假名
         其他 (0x80/0xA0-0xDF/0xFD-0xFF) → 映射到 Unicode 私有区 U+E000+byte
    """
    out = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b < 0x80:
            out.append(HIMITSU_TABLE[b])
            i += 1
            continue
        # 严格检查 SJIS 首字节合法范围
        is_sjis_lead = (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC)
        if is_sjis_lead and i + 1 < n:
            b2 = data[i+1]
            if (0x40 <= b2 <= 0x7E) or (0x80 <= b2 <= 0xFC):
                try:
                    ch = data[i:i+2].decode('cp932')
                    if len(ch) == 1:  # 只接受解成 1 个字符的情况
                        out.append(ch)
                        i += 2
                        continue
                except UnicodeDecodeError:
                    pass
        # fallback: 私有区
        out.append(chr(0xE000 + b))
        i += 1
    return ''.join(out)

def encode_himitsu_text(s: str) -> bytes:
    """Unicode → HIMITSU 字节流
       私有区 U+E0xx → 还原为原字节; 表里的字符用 token; 其他用 SJIS"""
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if 0xE000 <= cp <= 0xE0FF:
            out.append(cp - 0xE000)
        elif ch in _REV:
            out.append(_REV[ch])
        else:
            out += ch.encode('cp932', errors='replace')
    return bytes(out)
