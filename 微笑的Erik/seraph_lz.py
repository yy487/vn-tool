#!/usr/bin/env python3
"""
seraph_lz.py - Seraph引擎 LZ 压缩/解压模块

格式:
  Header: u32 LE 解压后大小
  Body:
    ctrl & 0x80 = 1: 回引 (2字节)
      offset = ((u16 >> 5) & 0x3FF) + 1   [1..1024]
      length = (u16 & 0x1F) + 1            [1..32]
    ctrl & 0x80 = 0: literal run
      length = (ctrl & 0x7F) + 1           [1..128]

逆向自 SERAPH.EXE FUN_004113b0
"""

import struct


def decompress(data: bytes) -> bytes:
    """LZ解压"""
    dec_size = struct.unpack_from('<I', data, 0)[0]
    out = bytearray()
    pos = 4

    while len(out) < dec_size and pos < len(data):
        ctrl = data[pos]; pos += 1

        if ctrl & 0x80:  # back-reference
            if pos >= len(data):
                break
            u16 = ctrl * 0x100 + data[pos]; pos += 1
            distance = ((u16 >> 5) & 0x3FF) + 1
            length = (u16 & 0x1F) + 1
            src = len(out) - distance
            for i in range(length):
                out.append(out[src + i])
        else:  # literal
            length = (ctrl & 0x7F) + 1
            out.extend(data[pos:pos + length])
            pos += length

    return bytes(out)


def compress(data: bytes) -> bytes:
    """LZ压缩 (贪心匹配)"""
    out = bytearray()
    out.extend(struct.pack('<I', len(data)))

    pos = 0
    while pos < len(data):
        # 尝试找最长回引匹配
        best_dist = 0
        best_len = 0
        max_dist = min(pos, 1024)
        max_len = min(32, len(data) - pos)

        for dist in range(1, max_dist + 1):
            src = pos - dist
            match_len = 0
            while match_len < max_len and data[src + match_len] == data[pos + match_len]:
                match_len += 1
            if match_len > best_len:
                best_len = match_len
                best_dist = dist

        if best_len >= 2:
            u16 = 0x8000 | ((best_dist - 1) << 5) | (best_len - 1)
            out.append((u16 >> 8) & 0xFF)
            out.append(u16 & 0xFF)
            pos += best_len
        else:
            # literal run
            run_start = pos
            run_len = 0
            while pos < len(data) and run_len < 128:
                if run_len >= 2:
                    # 检查下一个位置是否有足够好的匹配
                    max_d = min(pos, 1024)
                    max_l = min(32, len(data) - pos)
                    found = False
                    for d in range(1, max_d + 1):
                        ml = 0
                        s = pos - d
                        while ml < max_l and data[s + ml] == data[pos + ml]:
                            ml += 1
                        if ml >= 3:
                            found = True
                            break
                    if found:
                        break
                run_len += 1
                pos += 1

            out.append(run_len - 1)
            out.extend(data[run_start:run_start + run_len])

    return bytes(out)
