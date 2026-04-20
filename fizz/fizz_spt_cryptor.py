#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fizz ReVN::RxGSD::SPT Cryptor (独立模块 + CLI)

严格对齐 Core/SPT_Cryptor.cpp

算法:
  文件头 4B = [start_index ^ 0xF0, decode_type ^ 0xF0, un0, un1]
  body (从 offset 4 开始):
    decrypt = decode_round0(type) ∘ decode_round1(start)
    encrypt = encode_round1(start) ∘ encode_round0(type)  (逆序)

  decode_round0 (固定 byte 置换):
    type=0: swap2            type=1: swap4            type=2: perm8 [6,4,5,7,1,2,0,3]
  decode_round1 (位重排 + NOT):
    用 SG_TABLE[8*start+64 .. +72] 的 int8 做位移量
    正值左移, 负值右移, 最后 NOT

用法 (CLI):
  fizz_spt_cryptor.py decrypt in.spt out.bin
  fizz_spt_cryptor.py encrypt in.bin out.spt --ref orig.spt       # 从 orig.spt 头 4B 自动推参数
  fizz_spt_cryptor.py encrypt in.bin out.spt --start N --type N --un0 N --un1 N
  fizz_spt_cryptor.py info in.spt                                  # 显示真头参数
  fizz_spt_cryptor.py roundtrip in.spt                             # decrypt+encrypt 自检

库用法:
  from fizz_spt_cryptor import spt_decrypt, spt_encrypt, detect_keys
  dec = spt_decrypt(raw)                                  # 保留真头
  enc = spt_encrypt(dec, *detect_keys(raw))               # 用原参数回写
"""
import sys, struct, argparse
from pathlib import Path

# ============================================================================
# SG_TABLE: 128 个 int32 (带符号), 严格对齐源码
# ============================================================================
SG_TABLE = [
    0x00000005, 0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFA,
    0x00000006, 0x00000003, 0x00000000, 0xFFFFFFFD, 0x00000003, 0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE,
    0x00000007, 0x00000005, 0x00000003, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFB, 0xFFFFFFF9,
    0x00000003, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000003, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD,
    0x00000002, 0x00000003, 0x00000005, 0x00000002, 0xFFFFFFFD, 0x00000001, 0xFFFFFFFA, 0xFFFFFFFC,
    0x00000004, 0x00000004, 0x00000001, 0x00000004, 0x00000002, 0xFFFFFFFB, 0xFFFFFFFC, 0xFFFFFFFA,
    0x00000001, 0x00000002, 0x00000002, 0x00000003, 0x00000001, 0x00000002, 0xFFFFFFFC, 0xFFFFFFF9,
    0x00000002, 0xFFFFFFFF, 0x00000001, 0x00000004, 0x00000002, 0xFFFFFFFF, 0xFFFFFFFB, 0xFFFFFFFE,
    0x00000002, 0x00000006, 0xFFFFFFFF, 0x00000000, 0x00000001, 0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF,
    0x00000003, 0x00000004, 0x00000000, 0x00000003, 0xFFFFFFFD, 0x00000002, 0xFFFFFFFA, 0xFFFFFFFD,
    0x00000007, 0x00000005, 0x00000003, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFB, 0xFFFFFFF9,
    0x00000003, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000003, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD,
    0x00000006, 0x00000003, 0xFFFFFFFE, 0x00000004, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFB,
    0x00000005, 0x00000006, 0x00000004, 0xFFFFFFFF, 0xFFFFFFFC, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFC,
    0x00000007, 0xFFFFFFFF, 0x00000004, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFE,
    0x00000001, 0x00000005, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000001, 0x00000002, 0xFFFFFFFE, 0xFFFFFFFC,
]

def _s32(u):
    return u - 0x100000000 if u >= 0x80000000 else u

# ---------- round0: byte 置换 (自逆对称) ----------

def _round0(buf, dec_type):
    """swap2/swap4 自逆, perm8 需要区分编解码方向 (由 encode_round0 处理)."""
    n = len(buf)
    if dec_type == 0:
        for i in range(0, n - 1, 2):
            buf[i], buf[i+1] = buf[i+1], buf[i]
    elif dec_type == 1:
        for i in range(0, n - 3, 4):
            buf[i], buf[i+1], buf[i+2], buf[i+3] = buf[i+2], buf[i+3], buf[i], buf[i+1]
    elif dec_type == 2:
        for i in range(0, n - 7, 8):
            t = bytes(buf[i:i+8])
            # dec 映射 dst[i] = src[perm[i]], perm=[6,4,5,7,1,2,0,3]
            buf[i+0]=t[6]; buf[i+1]=t[4]; buf[i+2]=t[5]; buf[i+3]=t[7]
            buf[i+4]=t[1]; buf[i+5]=t[2]; buf[i+6]=t[0]; buf[i+7]=t[3]

def _round0_inv(buf, dec_type):
    """round0 的逆. swap2/swap4 自逆, perm8 需要反排列."""
    n = len(buf)
    if dec_type == 0 or dec_type == 1:
        _round0(buf, dec_type)  # 自逆
    elif dec_type == 2:
        for i in range(0, n - 7, 8):
            t = bytes(buf[i:i+8])
            # 逆: src[perm[i]] = dst[i]
            buf[i+6]=t[0]; buf[i+4]=t[1]; buf[i+5]=t[2]; buf[i+7]=t[3]
            buf[i+1]=t[4]; buf[i+2]=t[5]; buf[i+0]=t[6]; buf[i+3]=t[7]

# ---------- round1: 位重排 + NOT ----------

def _round1_decode(buf, start):
    if start >= 8:
        return
    shifts = [_s32(SG_TABLE[8*start + 64 + i]) for i in range(8)]
    for idx in range(len(buf)):
        b = buf[idx]
        dec = 0
        for i in range(8):
            sv = shifts[i]
            bit = (1 << i) & b
            if sv <= -1:
                dec |= bit >> abs(sv)
            else:
                dec |= bit << sv
        buf[idx] = (~dec) & 0xFF

def _round1_encode(buf, start):
    if start >= 8:
        return
    shifts = [_s32(SG_TABLE[8*start + 64 + i]) for i in range(8)]
    for idx in range(len(buf)):
        b = (~buf[idx]) & 0xFF
        orig = 0
        for i in range(8):
            sv = shifts[i]
            dst_bit = i + sv
            if 0 <= dst_bit <= 7:
                orig |= ((b >> dst_bit) & 1) << i
        buf[idx] = orig

# ============================================================================
# 公开 API
# ============================================================================

def detect_keys(raw):
    """从原始 SPT 文件头推 cryptor 参数. 返回 (start, type, un0, un1).

    注意: 若 raw 文件头被 spt_decrypt(make_readable=True) 改成 FF FF,
    此函数会推出 start=type=0x0F, 恰好 fd_fuduki 真头就是 FF FF,
    但其它游戏未必. 如果 SPT 来自 decrypt 的产物, 需要保存原始参数
    或使用 --ref 传入原文件.
    """
    if len(raw) < 4:
        raise ValueError("SPT 文件过短, 无法读取头 4B")
    return (raw[0] ^ 0xF0, raw[1] ^ 0xF0, raw[2], raw[3])

def spt_decrypt(data, make_readable=False):
    """解密 SPT. 默认保留真头 (make_readable=False), 与 encrypt 数据兼容."""
    buf = bytearray(data)
    start, dtype, _, _ = detect_keys(buf)
    body = bytearray(buf[4:])
    _round0(body, dtype)
    _round1_decode(body, start)
    buf[4:] = body
    if make_readable:
        buf[0] = 0xFF; buf[1] = 0xFF
    return bytes(buf)

def spt_encrypt(dec_data, start_index, decode_type, un0, un1):
    """加密. 需明确传入 4 参数 (通常从 detect_keys(原文件) 获得)."""
    buf = bytearray(dec_data)
    body = bytearray(buf[4:])
    _round1_encode(body, start_index)
    _round0_inv(body, decode_type)
    buf[4:] = body
    buf[0] = (start_index ^ 0xF0) & 0xFF
    buf[1] = (decode_type ^ 0xF0) & 0xFF
    buf[2] = un0 & 0xFF
    buf[3] = un1 & 0xFF
    return bytes(buf)

def spt_encrypt_with_ref(dec_data, ref_spt_path):
    """用参考 SPT 文件 (原版) 的头参数加密."""
    ref = open(ref_spt_path, 'rb').read()
    start, dtype, un0, un1 = detect_keys(ref)
    return spt_encrypt(dec_data, start, dtype, un0, un1)

# ============================================================================
# CLI
# ============================================================================

def cli_decrypt(args):
    raw = open(args.input, 'rb').read()
    start, dtype, un0, un1 = detect_keys(raw)
    print(f'[keys] start={start:#x} type={dtype:#x} un0={un0:#x} un1={un1:#x}', file=sys.stderr)
    dec = spt_decrypt(raw, make_readable=args.readable)
    Path(args.output).write_bytes(dec)
    print(f'[decrypt] {args.input} -> {args.output} ({len(dec)} bytes)', file=sys.stderr)

def cli_encrypt(args):
    dec = open(args.input, 'rb').read()
    if args.ref:
        ref = open(args.ref, 'rb').read()
        start, dtype, un0, un1 = detect_keys(ref)
        print(f'[keys from {args.ref}] start={start:#x} type={dtype:#x} un0={un0:#x} un1={un1:#x}', file=sys.stderr)
    else:
        if None in (args.start, args.type, args.un0, args.un1):
            print('需要 --ref 或同时指定 --start --type --un0 --un1', file=sys.stderr)
            sys.exit(1)
        start, dtype, un0, un1 = args.start, args.type, args.un0, args.un1
        print(f'[keys] start={start:#x} type={dtype:#x} un0={un0:#x} un1={un1:#x}', file=sys.stderr)
    enc = spt_encrypt(dec, start, dtype, un0, un1)
    Path(args.output).write_bytes(enc)
    print(f'[encrypt] {args.input} -> {args.output} ({len(enc)} bytes)', file=sys.stderr)

def cli_info(args):
    raw = open(args.input, 'rb').read()
    start, dtype, un0, un1 = detect_keys(raw)
    print(f'file: {args.input}')
    print(f'size: {len(raw)} bytes')
    print(f'head: {raw[:4].hex()}')
    print(f'  start_index = raw[0] ^ 0xF0 = {start:#04x}')
    type_name = {0: 'swap2', 1: 'swap4', 2: 'perm8'}.get(dtype, 'no-op (switch fallthrough)')
    print(f'  decode_type = raw[1] ^ 0xF0 = {dtype:#04x}  ({type_name})')
    print(f'  un0 = {un0:#04x}')
    print(f'  un1 = {un1:#04x}')

def cli_roundtrip(args):
    raw = open(args.input, 'rb').read()
    start, dtype, un0, un1 = detect_keys(raw)
    dec = spt_decrypt(raw, make_readable=False)
    enc = spt_encrypt(dec, start, dtype, un0, un1)
    ok = (enc == raw)
    print(f'[roundtrip] {args.input}: {"OK" if ok else "MISMATCH"}', file=sys.stderr)
    if not ok:
        diffs = [i for i, (a, b) in enumerate(zip(enc, raw)) if a != b]
        print(f'  diffs: {len(diffs)}  first 10: {[hex(x) for x in diffs[:10]]}', file=sys.stderr)
        sys.exit(1)

def main():
    ap = argparse.ArgumentParser(description='Fizz SPT Cryptor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_dec = sub.add_parser('decrypt', help='SPT → plain body')
    p_dec.add_argument('input')
    p_dec.add_argument('output')
    p_dec.add_argument('--readable', action='store_true', help='把头 2B 改成 FF FF (便于肉眼识别, 但丢失真参数!)')
    p_dec.set_defaults(func=cli_decrypt)

    p_enc = sub.add_parser('encrypt', help='plain body → SPT')
    p_enc.add_argument('input')
    p_enc.add_argument('output')
    p_enc.add_argument('--ref', help='参考 SPT 文件 (自动提取头参数)')
    p_enc.add_argument('--start', type=lambda x: int(x, 0))
    p_enc.add_argument('--type', type=lambda x: int(x, 0))
    p_enc.add_argument('--un0', type=lambda x: int(x, 0))
    p_enc.add_argument('--un1', type=lambda x: int(x, 0))
    p_enc.set_defaults(func=cli_encrypt)

    p_info = sub.add_parser('info', help='显示 SPT 头参数')
    p_info.add_argument('input')
    p_info.set_defaults(func=cli_info)

    p_rt = sub.add_parser('roundtrip', help='decrypt+encrypt 自检')
    p_rt.add_argument('input')
    p_rt.set_defaults(func=cli_roundtrip)

    args = ap.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
