#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bcs_lzss.py - Tanuki/Kaeru/Rune .bcs 用的 LZSS 编解码

参数 (与 BcsExtractor.cs / GARbro 一致):
  - 4KB 滑动窗口
  - frame 初始全 0, framePos 起始 = 0xFEE
  - 每个 control byte 控制 8 个后续 token, LSB 先
    bit=1: literal (1 字节)
    bit=0: match (2 字节)
        lo, hi = 两个字节
        offset = (hi & 0xF0) << 4 | lo
        count  = (~hi & 0xF) + 3        ; 即 (0x0F - (hi & 0x0F)) + 3, 范围 [3, 18]
  - 解码时 invert=True, 输出每字节按位取反 (内层 GMS 用)

外层 BCS/TSV 容器: invert=False
内层 GMS (老引擎字符串池): invert=True
内层 TNK (新引擎字符串池): 不用 LZSS, 用 Blowfish
"""

import struct


# ============================================================
# 解码
# ============================================================
def lzss_unpack(buf: bytes, skip: int, out_len: int, invert: bool = False) -> bytes:
    """从 buf[skip:] 解 LZSS, 直到产出 out_len 字节 (或输入耗尽)
    invert=True 时, 每个产出字节按位取反"""
    frame = bytearray(0x1000)
    fp = 0xFEE
    p = skip
    out = bytearray()
    ctl = 2
    n = len(buf)
    while len(out) < out_len:
        ctl >>= 1
        if ctl == 1:
            if p >= n:
                break
            ctl = buf[p] | 0x100
            p += 1
        if ctl & 1:
            if p >= n:
                break
            b = buf[p]; p += 1
            frame[fp & 0xFFF] = b; fp += 1
            out.append((~b) & 0xFF if invert else b)
        else:
            if p + 1 >= n:
                break
            lo, hi = buf[p], buf[p + 1]
            p += 2
            off = (hi & 0xF0) << 4 | lo
            cnt = min((~hi & 0xF) + 3, out_len - len(out))
            for _ in range(cnt):
                v = frame[off & 0xFFF]; off += 1
                frame[fp & 0xFFF] = v; fp += 1
                out.append((~v) & 0xFF if invert else v)
    return bytes(out)


# ============================================================
# 编码
# ============================================================
# 编码策略: 纯 literal 模式 (每个 control byte = 0xFF, 全部 literal token)
# 优点:
#   1. round-trip 兼容 (任何解码器都能正确还原)
#   2. 不需要实现复杂的滑动窗口匹配查找
#   3. 不会因匹配查找细节差异 (greedy/lazy/最长匹配偏好) 导致 round-trip 失败
# 代价: 输出体积 ≈ 原始 × 9/8 (每 8 个 literal byte 多 1 个 control byte)
# 因为外层文件本身已经够小, 体积代价可接受
#
# invert=True 时, 写入 literal 前先按位取反, 这样解码端 invert=True 取反后还原
def lzss_pack_literal(data: bytes, invert: bool = False) -> bytes:
    """纯 literal LZSS 编码; 每 8 字节一组, 前置 control=0xFF"""
    out = bytearray()
    n = len(data)
    i = 0
    while i < n:
        chunk = data[i:i + 8]
        out.append(0xFF)  # 8 个 literal token
        if invert:
            out.extend(((~b) & 0xFF) for b in chunk)
        else:
            out.extend(chunk)
        i += 8
    return bytes(out)


# ============================================================
# 自检 (执行本文件时跑)
# ============================================================
if __name__ == '__main__':
    import os, sys, random
    random.seed(42)

    print("[self-test] LZSS round-trip")
    test_cases = [
        b"",
        b"A",
        b"hello world" * 100,
        bytes(random.randint(0, 255) for _ in range(10000)),
        bytes(range(256)) * 30,
    ]
    for i, src in enumerate(test_cases):
        for inv in (False, True):
            packed = lzss_pack_literal(src, invert=inv)
            unpacked = lzss_unpack(packed, 0, len(src), invert=inv)
            ok = unpacked == src
            tag = "OK" if ok else "FAIL"
            print(f"  case {i} len={len(src):>6}  invert={inv}  "
                  f"packed={len(packed):>6}  ratio={len(packed)/max(1,len(src)):.3f}  [{tag}]")
            if not ok:
                sys.exit(1)
    print("[self-test] all passed")
