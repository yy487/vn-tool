#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI5WIN V6 codec - LZSS + MES structure
=======================================

剧情 MES:
  [LZSS 压缩流]
    └─解压后─> [u32 message_count]
               [u32 first_offsets[count]]   ← raw 相对 bytecode 起点
               [bytecode 区]

真实偏移 = raw_offset + count*4 + 4   (与参考工具 v2 约定一致)

UI MES (MAIN/SY*/SU*/EM* 等):
  未压缩, 以 magic `FE ED F1` 开头, 不含 first_offsets 表
  → 本工具不处理 UI MES (无连续剧本文本)
"""

import struct


# ---------------------------------------------------------------------------
# LZSS 解压缩
# ---------------------------------------------------------------------------

RING_SIZE = 0x1000
RING_INIT = 0xFEE
MIN_MATCH = 3
MAX_MATCH = 0x0F + MIN_MATCH   # 4 bit length + 3 = 18
MAX_OFFSET_DIST = 0x1000       # 12-bit offset


def lzss_decompress(src: bytes) -> bytes:
    """标准 AI5 V4 LZSS 解压.

    控制字节 LSB-first: bit=1 字面, bit=0 匹配引用.
    匹配 16 位编码: lo=offset 低 8 位, hi=offset 高 4 位 | length 低 4 位, length += 3.
    环形缓冲 0x1000, 起始 0xFEE, 初值 0x00.
    """
    ring = bytearray(RING_SIZE)
    ring_pos = RING_INIT
    dst = bytearray()
    src_pos = 0
    flags = 0
    flag_count = 0

    while src_pos < len(src):
        if flag_count == 0:
            flags = src[src_pos]
            src_pos += 1
            flag_count = 8

        bit = flags & 1
        flags >>= 1
        flag_count -= 1

        if bit:
            # 字面字节
            if src_pos >= len(src):
                break
            b = src[src_pos]
            src_pos += 1
            dst.append(b)
            ring[ring_pos] = b
            ring_pos = (ring_pos + 1) & 0xFFF
        else:
            # 匹配引用
            if src_pos + 1 >= len(src):
                break
            b1 = src[src_pos]
            b2 = src[src_pos + 1]
            src_pos += 2
            off = b1 | ((b2 & 0xF0) << 4)
            ln = (b2 & 0x0F) + MIN_MATCH
            for _ in range(ln):
                b = ring[off]
                off = (off + 1) & 0xFFF
                dst.append(b)
                ring[ring_pos] = b
                ring_pos = (ring_pos + 1) & 0xFFF
    return bytes(dst)


def lzss_compress(data: bytes) -> bytes:
    """伪 LZSS 压缩: 全字面模式.

    每 8 个字节前插入一个 0xFF flag 字节 (LSB-first 8 bit 全 1 = 8 个字面).
    解压器兼容, 注入速度快, 体积增大约 12.5%.
    不做匹配搜索, 因此不需要维护 ring buffer 状态.
    """
    out = bytearray()
    n = len(data)
    i = 0
    while i < n:
        chunk = data[i : i + 8]
        chunk_len = len(chunk)
        # flag 字节: chunk_len 个低位为 1, 高位为 0
        flag = (1 << chunk_len) - 1
        out.append(flag)
        out.extend(chunk)
        i += 8
    return bytes(out)


# ---------------------------------------------------------------------------
# MES 结构 (解压后)
# ---------------------------------------------------------------------------

class MesScript:
    """解压后的 MES 脚本: header + bytecode."""

    def __init__(self, message_count: int, first_offsets: list, bytecode: bytes):
        self.message_count = message_count
        self.first_offsets = first_offsets  # raw offsets, 相对 bytecode 起点
        self.bytecode = bytecode

    @classmethod
    def parse(cls, decompressed: bytes) -> 'MesScript':
        """从 LZSS 解压后的字节流解析."""
        count = struct.unpack_from('<I', decompressed, 0)[0]
        # 合理性检查: count*4 + 4 不能超过整个文件
        header_size = 4 + count * 4
        if header_size > len(decompressed):
            raise ValueError(f"Invalid MES: count={count} header_size={header_size} > file={len(decompressed)}")

        first_offsets = list(struct.unpack_from(f'<{count}I', decompressed, 4))
        bytecode = decompressed[header_size:]
        return cls(count, first_offsets, bytecode)

    def serialize(self) -> bytes:
        """序列化回解压后的字节流."""
        out = bytearray()
        out += struct.pack('<I', self.message_count)
        for o in self.first_offsets:
            out += struct.pack('<I', o)
        out += self.bytecode
        return bytes(out)

    def header_size(self) -> int:
        return 4 + self.message_count * 4

    def get_message_bytecode_offset(self, msg_idx: int) -> int:
        """MESSAGE 序号 -> bytecode 区内的偏移 (不是文件偏移)."""
        return self.first_offsets[msg_idx]


# ---------------------------------------------------------------------------
# 高层便捷 API
# ---------------------------------------------------------------------------

def load_mes(mes_bytes: bytes) -> MesScript:
    """从原始 MES 文件字节 (LZSS 压缩) 加载脚本."""
    decompressed = lzss_decompress(mes_bytes)
    return MesScript.parse(decompressed)


def save_mes(script: MesScript) -> bytes:
    """序列化 MES 并 LZSS 压缩."""
    decompressed = script.serialize()
    return lzss_compress(decompressed)


def is_compressed_story_mes(mes_bytes: bytes) -> bool:
    """判断一个 MES 是否是压缩的剧情文件 (vs 未压缩的 UI MES).
    
    UI MES 以固定魔数 FE ED F1 1B 开头.
    """
    return not (len(mes_bytes) >= 4 and mes_bytes[:4] == b'\xfe\xed\xf1\x1b')
