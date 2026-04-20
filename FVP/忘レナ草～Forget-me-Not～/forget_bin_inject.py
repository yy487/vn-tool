#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
forget_bin_inject.py  --  JSON → 新 textdata.bin + 全脚本重映射

汉化注入流程:
  1. 读 JSON, 按原 id 顺序拼出新的 textdata.bin
       新结构和原版一致: [\\x00\\x00] [text \\x00 u16_uid]*
       新文本 length 不限, u16_uid 全部沿用原值, 不重新编号
       (引擎拿 uid 做回想/存档索引, 改了会丢档)
  2. 建立 old_text_offset → new_text_offset 映射表
  3. 扫描所有其它 .bin 脚本, 仅替换 MES(0x1A) / TLK(0x1B) / MENU(0x1C)
     这三个 opcode 紧前面的那一个 u32 立即数 — 即字节序列
        03 [u32_imm]   <op>
     的 u32_imm 部分. 这是经过验证唯一能 100% 命中、零误报的位置.
  4. 写出整套新文件 (textdata.bin + 所有改过的 cXXXX.bin / sy*.bin / ...).

注意:
  - 默认按 CP932 编码. 中文译文要走这条路必须先在游戏端做字体 hook
    或使用 SJIS↔GBK 转换表 (本工具不强制做这件事, 留给上游).
  - --encoding gbk 可强行用 GBK 编码 (仅当你已经 hook 字体确认 OK 时使用).
  - inject 之后请用 verify 子命令做 round-trip 自检, 不通过别往封包送.
"""

import os, sys, struct, json, argparse, shutil

# 文本载体 opcode: MES/TLK/MENU. 它们的"文本偏移"参数都是 opcode 紧前面那一个 imm.
# (TLK 有 3 个 imm 参数, 但栈顶 = 文本偏移, 也是紧前 1 个 imm)
TEXT_OPCODES = {0x1A, 0x1B, 0x1C}


# ----------------------------------------------------------------------
# textdata 读 / 写
# ----------------------------------------------------------------------

def parse_textdata(td: bytes):
    """返回 (records, head_pad, tail_pad).
    records = [(byte_offset, text_bytes, u16_id), ...]
    head_pad = 文件开头无意义的填充字节 (通常 b'\\x00\\x00')
    tail_pad = 文件末尾不构成完整记录的孤儿字节 (有的版本会有 ~9 字节)
    """
    head = b''
    if td[:2] == b'\x00\x00':
        head = td[:2]
        i = 2
    else:
        i = 0
    recs = []
    last_end = i
    while i < len(td):
        j = td.find(b'\x00', i)
        if j == -1:
            break
        if j + 3 > len(td):
            break
        text = td[i:j]
        idn = struct.unpack_from('<H', td, j + 1)[0]
        recs.append((i, text, idn))
        i = j + 3
        last_end = i
    tail = td[last_end:]
    return recs, head, tail


def build_new_textdata(orig_recs, head_pad, tail_pad,
                       json_entries, encoding='cp932'):
    """
    orig_recs    = parse_textdata(原)[0]
    head_pad     = 原文件头 padding (通常 b'\\x00\\x00')
    tail_pad     = 原文件尾 padding (通常 b'' 或 ~9 字节)
    json_entries = [{'id':old_off, 'uid':u16, 'message':str}, ...]
    返回: (new_td_bytes, idx_map_old_to_new)
    """
    by_old_off = {r[0]: (r[1], r[2]) for r in orig_recs}
    new_text_for = {}
    for e in json_entries:
        old_off = e['id']
        if old_off not in by_old_off:
            raise ValueError(f'JSON id {old_off:#x} 不存在于原 textdata 中')
        msg = e.get('message', '')
        try:
            new_text_for[old_off] = msg.encode(encoding)
        except UnicodeEncodeError as ex:
            raise ValueError(
                f'id {old_off:#x} 编码失败 ({encoding}): {ex} '
                f'message={msg!r}')

    out = bytearray(head_pad)
    idx_map = {}
    for old_off, raw, uid in orig_recs:
        new_off = len(out)
        idx_map[old_off] = new_off
        body = new_text_for.get(old_off, raw)
        out.extend(body)
        out.append(0x00)
        out.extend(struct.pack('<H', uid))
    out.extend(tail_pad)
    return bytes(out), idx_map


# ----------------------------------------------------------------------
# 脚本扫描 / 重映射
# ----------------------------------------------------------------------

def remap_script(data: bytes, idx_map: dict) -> tuple:
    """
    扫描 .bin 字节码, 替换所有 MES/TLK/MENU 紧前的 u32 立即数 (文本偏移).
    返回 (new_bytes, n_patched).
    """
    out = bytearray(data)
    i = 0
    n = 0
    while i < len(out):
        b = out[i]
        if b == 0x03:                              # imm32 prefix
            i += 5
            continue
        if b in TEXT_OPCODES:
            if i >= 5 and out[i - 5] == 0x03:
                old = struct.unpack_from('<I', out, i - 4)[0]
                if old in idx_map:
                    new = idx_map[old]
                    struct.pack_into('<I', out, i - 4, new)
                    if new != old:
                        n += 1
            i += 1
            continue
        i += 1
    return bytes(out), n


# ----------------------------------------------------------------------
# 命令: inject
# ----------------------------------------------------------------------

def cmd_inject(args):
    td_orig = open(os.path.join(args.indir, 'textdata.bin'), 'rb').read()
    orig_recs, head_pad, tail_pad = parse_textdata(td_orig)
    print(f'[+] 原 textdata.bin: {len(td_orig)} 字节, {len(orig_recs)} 条 '
          f'(head_pad={len(head_pad)}B, tail_pad={len(tail_pad)}B)')

    with open(args.json, 'r', encoding='utf-8') as f:
        entries = json.load(f)
    print(f'[+] JSON: {len(entries)} 条 (encoding={args.encoding})')

    new_td, idx_map = build_new_textdata(
        orig_recs, head_pad, tail_pad, entries, encoding=args.encoding)
    print(f'[+] 新 textdata.bin: {len(new_td)} 字节 '
          f'(Δ {len(new_td)-len(td_orig):+d})')

    # 准备输出目录
    os.makedirs(args.outdir, exist_ok=True)

    # 复制 indir 下所有文件到 outdir, 然后覆盖 textdata.bin + 改写脚本
    for fn in os.listdir(args.indir):
        src = os.path.join(args.indir, fn)
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(args.outdir, fn))

    with open(os.path.join(args.outdir, 'textdata.bin'), 'wb') as f:
        f.write(new_td)

    total_patched = 0
    files_changed = 0
    for fn in sorted(os.listdir(args.outdir)):
        if not fn.endswith('.bin'):
            continue
        if fn in ('textdata.bin', 'branch.bin'):
            continue
        path = os.path.join(args.outdir, fn)
        data = open(path, 'rb').read()
        new_data, n = remap_script(data, idx_map)
        if n > 0 or new_data != data:
            with open(path, 'wb') as f:
                f.write(new_data)
            files_changed += 1
            total_patched += n
    print(f'[+] 重映射: {total_patched} 处, {files_changed} 个脚本文件改动')
    print(f'[ok] 输出目录: {args.outdir}')


# ----------------------------------------------------------------------
# 命令: verify  (round-trip 自检)
# ----------------------------------------------------------------------

def cmd_verify(args):
    """
    输入: 原 decompressed 目录
    流程:
      1. extract 原 textdata.bin → temp JSON (不修改任何文本)
      2. inject  temp JSON       → temp 输出目录
      3. 重新 extract temp 输出目录的 textdata.bin
      4. 三方对比: 原 JSON 应与新 JSON 完全一致;
         所有非 textdata 脚本应与原版字节级一致 (因为 idx_map[old]==old)
    """
    import tempfile

    td_orig = open(os.path.join(args.indir, 'textdata.bin'), 'rb').read()
    orig_recs, head_pad, tail_pad = parse_textdata(td_orig)
    fake_json = [{'id': o, 'uid': u, 'name': '', 'message': t.decode('cp932')}
                 for o, t, u in orig_recs]

    tmp = tempfile.mkdtemp(prefix='forget_rt_')
    try:
        json_path = os.path.join(tmp, 'orig.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(fake_json, f, ensure_ascii=False)

        out_dir = os.path.join(tmp, 'out')
        class _A: pass
        a = _A()
        a.indir = args.indir
        a.json = json_path
        a.outdir = out_dir
        a.encoding = 'cp932'
        cmd_inject(a)

        new_td = open(os.path.join(out_dir, 'textdata.bin'), 'rb').read()

        ok = True
        # 1) textdata 字节级一致 (恒等映射, 不改一字)
        if new_td != td_orig:
            print(f'[FAIL] textdata.bin 字节不一致: '
                  f'{len(td_orig)} → {len(new_td)}')
            ok = False
        else:
            print(f'[ok] textdata.bin 字节级一致 ({len(new_td)} bytes)')

        new_recs, _, _ = parse_textdata(new_td)
        if len(new_recs) != len(orig_recs):
            print(f'[FAIL] 条目数不同: {len(orig_recs)} vs {len(new_recs)}')
            ok = False

        # 2) 所有 .bin 脚本应当字节级一致 (idx_map 全部恒等)
        bin_files = [f for f in sorted(os.listdir(out_dir))
                     if f.endswith('.bin') and f not in
                     ('textdata.bin', 'branch.bin')]
        diff_files = []
        for fn in bin_files:
            old = open(os.path.join(args.indir, fn), 'rb').read()
            new = open(os.path.join(out_dir, fn), 'rb').read()
            if old != new:
                diff_files.append(fn)
        if diff_files:
            print(f'[FAIL] {len(diff_files)} 个脚本字节不一致, '
                  f'前 5: {diff_files[:5]}')
            ok = False
        else:
            print(f'[ok] {len(bin_files)} 个脚本字节级一致')

        print()
        print('[ok] round-trip PASS' if ok else '[!!] round-trip FAILED')
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _scan_text_refs(data: bytes):
    """返回 [(opcode_pos, text_offset), ...]."""
    refs = []
    i = 0
    while i < len(data):
        if data[i] == 0x03:
            i += 5
            continue
        if data[i] in TEXT_OPCODES:
            if i >= 5 and data[i-5] == 0x03:
                v = struct.unpack_from('<I', data, i-4)[0]
                refs.append((i, v))
        i += 1
    return refs


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='forget.exe textdata injector')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('inject', help='把 JSON 译文写回 textdata + 重映射脚本')
    p.add_argument('indir',  help='原始 decompressed 目录 (含 textdata.bin & .bin 脚本)')
    p.add_argument('json',   help='GalTransl 风格 JSON')
    p.add_argument('-o', '--outdir', required=True,
                   help='输出目录 (会被覆盖)')
    p.add_argument('--encoding', default='cp932',
                   choices=['cp932', 'gbk'],
                   help='文本编码 (默认 cp932)')
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser('verify', help='恒等 round-trip 自检')
    p.add_argument('indir')
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    rc = args.func(args)
    sys.exit(rc or 0)


if __name__ == '__main__':
    main()
