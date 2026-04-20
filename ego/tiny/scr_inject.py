#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scr_inject.py  —  Studio e.go!/TwinWay BSF1 脚本文本变长注入器

把 scr_extract 产出的 JSON 翻译写回 .scr, 支持变长 (译文长度 ≠ 原文)。

变长注入核心逻辑:
    1. 完整反汇编原 scr, 得到 (labels, insns)
    2. 逐条指令重新打包, 文本条目换成翻译后的 CP932 字节
    3. 建立 old_pc → new_pc 映射
    4. 因为 JUMP/CALL 的 target 是 **标签名字符串** 而非 offset,
       所有非文本指令的 raw 不需要修改, 只需更新标签表里每个
       label 的 offset 字段
    5. 最终: magic + 新标签表 + 拼接的 bytecode

用法:
    python scr_inject.py inject Daytalk.scr daytalk.json Daytalk_new.scr
    python scr_inject.py verify original.scr rebuilt.scr
    python scr_inject.py batch  origdir/ jsondir/ outdir/
"""
import os
import sys
import json
import struct
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bsf1_codec import (
    disasm_all, build_label_table, MAGIC, ParseError,
)


class InjectError(Exception):
    pass


# ---- 核心注入逻辑 --------------------------------------------------------

def _parse_pc(v):
    """JSON 里的 pc 字段可能是 '0x578' 或 int, 统一转 int."""
    if isinstance(v, int):
        return v
    return int(v, 0)


def inject_one(scr_data: bytes, trans: list) -> bytes:
    """接收原 scr 字节 + 翻译条目列表, 返回注入后字节."""
    labels, bc_start, _, insns, trailer = disasm_all(scr_data)

    # 建立 pc → 翻译 映射
    trans_by_pc = {}
    for item in trans:
        if 'pc' not in item:
            raise InjectError('JSON 条目缺少 pc 字段, 无法定位')
        trans_by_pc[_parse_pc(item['pc'])] = item

    # 第一遍: 构建每条指令的新 raw, 同时算 old_pc → new_pc
    new_blobs = []
    old_to_new = {}
    new_pc = bc_start  # 临时以原 bc_start 起算, 最后统一加 shift
    text_hit = 0
    text_total = 0
    for insn in insns:
        old_to_new[insn['pc']] = new_pc
        if insn['kind'] == 'text':
            text_total += 1
            tr = trans_by_pc.get(insn['pc'])
            if tr is not None and 'message' in tr:
                msg = tr['message']
                try:
                    new_bytes = msg.encode('cp932') + b'\x00'
                except UnicodeEncodeError as e:
                    raise InjectError(
                        f'PC {insn["pc"]:#x} 文本含 CP932 无法编码的字符: '
                        f'{msg!r}\n    {e}')
                new_blobs.append(new_bytes)
                new_pc += len(new_bytes)
                text_hit += 1
            else:
                new_blobs.append(bytes(insn['raw']))
                new_pc += len(insn['raw'])
        else:
            # 非文本指令: raw 不变 (JUMP target 是标签名字符串)
            new_blobs.append(bytes(insn['raw']))
            new_pc += len(insn['raw'])

    # 第二遍: 重建标签表 (所有 labels 都是真标签, 全部映射)
    new_labels = []
    for name, old_off in labels:
        if old_off not in old_to_new:
            raise InjectError(
                f'label {name!r} offset {old_off:#x} 不在任何指令起点上')
        new_labels.append((name, old_to_new[old_off]))

    # 计算真正的 bc_start: magic(4) + 标签表大小 (含 trailer)
    new_label_table = build_label_table(new_labels, trailer)
    new_bc_start = 4 + len(new_label_table)
    shift = new_bc_start - bc_start

    if shift != 0:
        new_labels = [(n, off + shift) for n, off in new_labels]
        new_label_table = build_label_table(new_labels, trailer)

    # 拼装最终字节
    new_bytecode = b''.join(new_blobs)
    out = MAGIC + new_label_table + new_bytecode

    # sanity
    first_insn_new_pc = min(old_to_new.values()) + shift
    if first_insn_new_pc != new_bc_start:
        raise InjectError(
            f'内部错误: 首指令 new_pc={first_insn_new_pc:#x} '
            f'!= new_bc_start={new_bc_start:#x}')

    print(f'  指令: {len(insns)}, 文本: {text_hit}/{text_total} 翻译, '
          f'大小: {len(scr_data)} → {len(out)} bytes')
    return out


# ---- CLI ------------------------------------------------------------------

def cmd_inject(args):
    scr_data = open(args.scr, 'rb').read()
    trans = json.load(open(args.json, encoding='utf-8'))
    try:
        out = inject_one(scr_data, trans)
    except InjectError as e:
        print(f'[!] {args.scr}: {e}')
        sys.exit(1)
    with open(args.out, 'wb') as f:
        f.write(out)
    print(f'[✓] {args.scr} + {args.json} → {args.out}')


def cmd_batch(args):
    os.makedirs(args.outdir, exist_ok=True)
    ok = 0
    failed = []
    for root, _, files in os.walk(args.scrdir):
        for fn in files:
            if not fn.lower().endswith('.scr'):
                continue
            scr_path = os.path.join(root, fn)
            rel = os.path.relpath(scr_path, args.scrdir)
            json_path = os.path.join(args.jsondir,
                                     os.path.splitext(rel)[0] + '.json')
            if not os.path.exists(json_path):
                # 无翻译 → 直接复制原文件
                out_path = os.path.join(args.outdir, rel)
                os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
                with open(out_path, 'wb') as f:
                    f.write(open(scr_path, 'rb').read())
                continue
            out_path = os.path.join(args.outdir, rel)
            os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
            try:
                scr_data = open(scr_path, 'rb').read()
                trans = json.load(open(json_path, encoding='utf-8'))
                out = inject_one(scr_data, trans)
                with open(out_path, 'wb') as f:
                    f.write(out)
                ok += 1
                if ok % 20 == 0:
                    print(f'  [{ok}] {rel}')
            except (InjectError, ParseError, Exception) as e:
                failed.append((scr_path, str(e)))
                print(f'[!] {rel}: {e}')
    print(f'\n✓ 批量注入完成: {ok} 成功, {len(failed)} 失败')
    for p, e in failed[:10]:
        print(f'   {p}: {e}')


def cmd_verify(args):
    """对比两个 scr 的反汇编结果 (允许偏移整体平移)."""
    a = open(args.a, 'rb').read()
    b = open(args.b, 'rb').read()

    la, _, _, ia, _ = disasm_all(a)
    lb, _, _, ib, _ = disasm_all(b)

    ok = True
    print(f'{args.a}: {len(a)} bytes, {len(la)} labels, {len(ia)} insns')
    print(f'{args.b}: {len(b)} bytes, {len(lb)} labels, {len(ib)} insns')

    if len(la) != len(lb):
        print(f'✗ 标签数量不同'); ok = False
    else:
        label_mismatch = sum(1 for (na, _), (nb, _) in zip(la, lb) if na != nb)
        if label_mismatch:
            print(f'✗ 标签名不一致: {label_mismatch} 处'); ok = False

    if len(ia) != len(ib):
        print(f'✗ 指令数不同'); ok = False
    else:
        text_diff = 0
        op_diff = 0
        for x, y in zip(ia, ib):
            if x['kind'] != y['kind']:
                op_diff += 1
                continue
            if x['kind'] == 'op':
                if x.get('name') != y.get('name') or x.get('args') != y.get('args'):
                    op_diff += 1
            else:
                if x['text'] != y['text']:
                    text_diff += 1
        if op_diff:
            print(f'✗ 指令 (op) 不一致: {op_diff} 处'); ok = False
        if text_diff:
            print(f'  文本差异: {text_diff} 处 (正常, 翻译引入)')

    if a == b:
        print('✓ 字节级完全一致 (bit-perfect round-trip)')
    elif ok:
        print('✓ 反汇编级一致 (存在文本差异, 结构正确)')


def main():
    ap = argparse.ArgumentParser(
        description='Studio e.go!/TwinWay BSF1 脚本文本注入器')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('inject', help='注入单个 scr')
    p.add_argument('scr')
    p.add_argument('json')
    p.add_argument('out')
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser('batch', help='批量注入')
    p.add_argument('scrdir')
    p.add_argument('jsondir')
    p.add_argument('outdir')
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser('verify', help='比对两个 scr 的反汇编')
    p.add_argument('a')
    p.add_argument('b')
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
