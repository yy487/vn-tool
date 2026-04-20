#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2/ISF 脚本加解密模块
引擎: SM2MPX10 (ペンギンワークス, HIMITSU 等)

算法:
    每个 .ISF 脚本文件在封包内以 XOR 0xFF 整体加密。
    解密即再异或一次 0xFF 还原明文。对称算法,encrypt = decrypt。

验证:
    明文前 8 字节为两个负 int32 (长度/大小字段的补码形式),
    异或 0xFF 后变为正数 u32,形如 [script_size, sub_size]。
    从 0x08 开始是严格递增的 u32 偏移表。

用法:
    # 作为模块 import
    from isf_crypt import decrypt_isf, encrypt_isf
    plain = decrypt_isf(cipher_bytes)
    cipher = encrypt_isf(plain_bytes)

    # 命令行单文件
    python isf_crypt.py dec EV001.ISF EV001.dec
    python isf_crypt.py enc EV001.dec EV001.ISF

    # 命令行整个目录 (in-place, 按扩展名筛选)
    python isf_crypt.py dec-dir ./mes
    python isf_crypt.py enc-dir ./mes
"""
import os, sys, argparse, struct

XOR_KEY = 0xFF
HEADER_PLAIN = 8  # 前 8 字节 (head_len u32 + version u16 + key u8 + pad u8) 保持明文

def _xor(data: bytes) -> bytes:
    """SM2 MPX 0xD197 加密: 只对 [8:] 异或 0xFF, 前 8 字节明文"""
    if len(data) <= HEADER_PLAIN:
        return data
    out = bytearray(data[:HEADER_PLAIN])
    out += bytes(b ^ XOR_KEY for b in data[HEADER_PLAIN:])
    return bytes(out)

def decrypt_isf(data: bytes) -> bytes:
    """解密 .ISF 密文为明文脚本字节。"""
    return _xor(data)

def encrypt_isf(data: bytes) -> bytes:
    """把明文脚本字节加密回 .ISF 封包内格式。"""
    return _xor(data)

def verify_plaintext(plain: bytes) -> bool:
    """
    启发式验证: head_len 字段合理 + offsetlist 严格递增落在文件内
    """
    if len(plain) < 0x18:
        return True  # 太短直接放过
    size = len(plain)
    head_len = struct.unpack_from('<I', plain, 0)[0]
    if head_len < 8 or head_len > size or (head_len - 8) % 4 != 0:
        return False
    # 检查 offsetlist 前 4 项递增且落在 body 区间
    if head_len >= 0x18:
        vals = struct.unpack_from('<4I', plain, 0x08)
        body_size = size - head_len
        if not all(vals[i] < vals[i+1] for i in range(3)):
            return False
        if vals[-1] >= body_size:
            return False
    return True

# --------------------- CLI ---------------------

def _process_file(in_path: str, out_path: str, mode: str) -> None:
    with open(in_path, 'rb') as f:
        data = f.read()
    out = decrypt_isf(data) if mode == 'dec' else encrypt_isf(data)
    with open(out_path, 'wb') as f:
        f.write(out)
    tag = '[dec]' if mode == 'dec' else '[enc]'
    ok = ''
    if mode == 'dec':
        ok = ' OK' if verify_plaintext(out) else ' ?? (未通过明文启发式)'
    print(f'{tag} {in_path} -> {out_path} ({len(data)} bytes){ok}')

def _process_dir(dir_path: str, mode: str, exts=('.isf',)) -> None:
    exts = tuple(e.lower() for e in exts)
    count = 0
    for name in sorted(os.listdir(dir_path)):
        if not name.lower().endswith(exts):
            continue
        p = os.path.join(dir_path, name)
        if not os.path.isfile(p):
            continue
        _process_file(p, p, mode)
        count += 1
    print(f'[+] {mode}: 处理 {count} 个文件 @ {dir_path}')

def main():
    ap = argparse.ArgumentParser(description='SM2/ISF XOR 0xFF 加解密工具')
    sub = ap.add_subparsers(dest='cmd', required=True)

    d = sub.add_parser('dec', help='解密单个文件')
    d.add_argument('src'); d.add_argument('dst')

    e = sub.add_parser('enc', help='加密单个文件')
    e.add_argument('src'); e.add_argument('dst')

    dd = sub.add_parser('dec-dir', help='原地解密目录内所有 .isf')
    dd.add_argument('dir')
    dd.add_argument('--ext', default='.isf', help='文件扩展名 (默认 .isf)')

    ed = sub.add_parser('enc-dir', help='原地加密目录内所有 .isf')
    ed.add_argument('dir')
    ed.add_argument('--ext', default='.isf', help='文件扩展名 (默认 .isf)')

    args = ap.parse_args()
    if args.cmd == 'dec':
        _process_file(args.src, args.dst, 'dec')
    elif args.cmd == 'enc':
        _process_file(args.src, args.dst, 'enc')
    elif args.cmd == 'dec-dir':
        _process_dir(args.dir, 'dec', exts=(args.ext,))
    elif args.cmd == 'enc-dir':
        _process_dir(args.dir, 'enc', exts=(args.ext,))

if __name__ == '__main__':
    main()
