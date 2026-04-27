#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai5winv7_mes_inject.py — GalTransl JSON → V7 (愛しの言霊) MES 回注

流程:
  1. 读 GalTransl JSON (translate 后的 name/message)
  2. 读原 MES, 解压 + 反汇编得到指令流
  3. 按 _meta.name_insn_idx / msg_insn_idx 用翻译文本 (CP932 编码, 经字符表映射)
     替换对应 TEXT 指令的 args[0] 字节
  4. 重新 assemble (第一遍), 记录 "旧 offset → 新 offset" 映射
  5. 扫描所有 JUMP/JUMP_IF/INTERRUPT_IF, 修正 I 字段 (跳转目标)
  6. 再 assemble 一次 (I 固定 4 字节, 长度不变, 一次收敛)
  7. 伪 LZSS 压缩 → 写入目标 MES 文件

文本编码策略 (与 AI5 V4/V5 一致):
  - 输出 **CP932** (不转 GBK)
  - 半角字母 / 数字 / ASCII 符号 → 全角 (游戏字体按全角渲染)
  - 特殊符号表 (♡/♪ 等) 按需扩展
  - 不能 cp932 编码的字符会报 fail-fast 错误

id 格式: "FILENAME#idx" (和 extract 严格一致)

用法:
  ai5winv7_mes_inject.py single <orig_mes> <json> <out_mes>
  ai5winv7_mes_inject.py batch  <orig_dir> <json_dir> <out_dir>
  ai5winv7_mes_inject.py verify <orig_mes> <json>       # dry run, 不写文件
"""
import os
import sys
import json
import struct
import argparse

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
from ai5v7_bytecode_v2 import (
    lzss_decompress, lzss_compress_fake,
    disassemble, assemble, OPCODES,
)


# ---------------------------------------------------------------------------
# 文本编码: 半角→全角 + 特殊符号
# ---------------------------------------------------------------------------
# ASCII → 全角 (U+0021-U+007E → U+FF01-U+FF5E, 空格 → U+3000)
def halfwidth_to_fullwidth(s):
    out = []
    for ch in s:
        code = ord(ch)
        if code == 0x20:
            out.append('\u3000')  # 全角空格
        elif 0x21 <= code <= 0x7E:
            out.append(chr(code - 0x21 + 0xFF01))
        else:
            out.append(ch)
    return ''.join(out)


# 特殊符号映射 (超出 CP932 范围的需要替换)
SPECIAL_CHAR_MAP = {
    '♡': '♥',     # CP932 不含 ♡, 用 ♥ (0x81F1) 代替
    # 按需扩展: ♪, ★, ☆, ♂, ♀ 都在 CP932 里, 无需映射
}


def encode_cp932(s, full_width=True, allow_halfwidth=False):
    """把翻译字符串 s 编码成 CP932 字节流.
    full_width: 半角 → 全角
    allow_halfwidth: 如果 True 则保留半角 ASCII (用于角色名, 避免全角化破坏短名)
    """
    for old, new in SPECIAL_CHAR_MAP.items():
        s = s.replace(old, new)
    if full_width and not allow_halfwidth:
        s = halfwidth_to_fullwidth(s)
    try:
        return s.encode('cp932')
    except UnicodeEncodeError as e:
        # 找出罪魁祸首
        bad_ch = s[e.start:e.end]
        raise ValueError(
            f'无法 CP932 编码字符 {bad_ch!r} (pos {e.start}), '
            f'在字符串中: ...{s[max(0,e.start-10):e.end+10]!r}... — '
            f'请添加到 SPECIAL_CHAR_MAP'
        )


# ---------------------------------------------------------------------------
# 替换 TEXT 指令的字节
# ---------------------------------------------------------------------------
def replace_text_insn(insns, idx, new_bytes):
    """把 insns[idx] 的 TEXT 字节改成 new_bytes. idx 必须指向 op 0x01 TEXT."""
    insn = insns[idx]
    if not (insn[0] == 'OP' and insn[2] == 0x01):
        raise ValueError(f'insn[{idx}] 不是 TEXT, 而是 {insn}')
    kind, pos, op, name, args = insn
    # args 是 [text_bytes], 替换为 new_bytes
    new_args = [new_bytes]
    insns[idx] = (kind, pos, op, name, new_args)


# ---------------------------------------------------------------------------
# 跳转 fixup
# ---------------------------------------------------------------------------
# 跳转 opcode 及目标参数在 args 中的下标
#   0x09 JUMP_IF      (CI)  → I  = args[1]  (4B)
#   0x0a JUMP         (I)   → I  = args[0]  (4B)
#   0x0e MENU_INIT    (CVH) → H  = args[2]  (2B) ← 隐藏 skip target
#   0x12 INTERRUPT_IF (CI)  → I  = args[1]  (4B)
#
# MENU_INIT 的 u16 skip target 发现历史:
#   原工具把 0x0e 的格式标成 'CV', 导致后面的 2 字节 u16 被当作独立的
#   TEXT2/SJIS run. identity inject 字节级一致 (巧合), 但变长 inject 后
#   target 不随之移动, 菜单跳到错误位置 → C 求值器报 "スタックにデータが
#   残っています". 详见 TEMPLE.MES 自宅菜单 case, 在 486 个 MES 上共 160
#   条 MENU_INIT, 修复后 target 全部落在合法指令起点.
#
# fixup 机制对 H/I 无差别:  write_args 按 fmt 字符自动选 2/4 字节写回,
# 这里只需把 MENU_INIT 加入映射表即可, fixup_jumps 和 assemble_with_offset_map
# 都不用改.
JUMP_OPS = {
    0x09: 1,
    0x0A: 0,
    0x0E: 2,   # MENU_INIT skip target
    0x12: 1,
}


def collect_jump_targets(insns):
    """返回 [(idx, arg_pos, old_target), ...]"""
    out = []
    for i, insn in enumerate(insns):
        if insn[0] == 'OP' and insn[2] in JUMP_OPS:
            arg_pos = JUMP_OPS[insn[2]]
            target = insn[4][arg_pos]
            out.append((i, arg_pos, target))
    return out


def assemble_with_offset_map(insns):
    """Assemble 并返回 (bytes, old_pos_to_new_pos dict, new_insns_with_updated_pos).

    注意: insns 里每条指令的第 2 个字段是 **原始** 偏移 (反汇编时记录).
    我们扫描每条指令, 用当前 buf 长度作为其新 offset, 构建映射.
    """
    from ai5v7_bytecode_v2 import write_args
    buf = bytearray()
    old_to_new = {}
    new_insns = []
    for insn in insns:
        old_pos = insn[1]
        new_pos = len(buf)
        old_to_new[old_pos] = new_pos

        if insn[0] == 'OP':
            _, _, op, name, args = insn
            buf.append(op)
            fmt = OPCODES[op][1]
            write_args(args, fmt, buf)
            new_insns.append(('OP', new_pos, op, name, args))
        elif insn[0] in ('SJIS', 'TEXT2'):
            _, _, run, term = insn
            buf += run
            if term:
                buf.append(0)
            new_insns.append((insn[0], new_pos, run, term))
    return bytes(buf), old_to_new, new_insns


def fixup_jumps(insns, old_to_new):
    """遍历 insns, 把所有 JUMP/JUMP_IF/INTERRUPT_IF 的 I 参数通过 old_to_new 映射.
    原地修改 insns 里的 args 列表."""
    unresolved = []
    for i, insn in enumerate(insns):
        if insn[0] != 'OP' or insn[2] not in JUMP_OPS:
            continue
        arg_pos = JUMP_OPS[insn[2]]
        old_tgt = insn[4][arg_pos]
        new_tgt = old_to_new.get(old_tgt)
        if new_tgt is None:
            # 可能是指向文件末尾 (= len(data))
            unresolved.append((i, insn[2], old_tgt))
            continue
        # 修改 args - args 是 list, 可以原地改
        insn[4][arg_pos] = new_tgt
    return unresolved


# ---------------------------------------------------------------------------
# 核心 inject
# ---------------------------------------------------------------------------
def inject_one(orig_mes_path, json_path, out_mes_path=None, verify_only=False):
    """对单个 MES 执行 inject, 返回 (成功条目数, 警告列表)."""
    # 读原 MES
    raw = open(orig_mes_path, 'rb').read()
    plain = lzss_decompress(raw)
    insns_tuple = disassemble(plain)

    # 把 insns 的 args 列表转成 mutable (原 disassemble 返回 tuple)
    # 这里 insns 是 list of tuple, tuple 里 args 是 list, 本就 mutable
    # 但为了修改 args[pos], 我们要保证 insn[4] 是 list, 不是 tuple
    insns = []
    for insn in insns_tuple:
        if insn[0] == 'OP':
            kind, pos, op, name, args = insn
            insns.append([kind, pos, op, name, list(args)])
        else:
            insns.append(list(insn))

    # 读 JSON
    with open(json_path, 'r', encoding='utf-8') as f:
        entries = json.load(f)

    # 应用翻译
    replaced = 0
    warnings = []
    for entry in entries:
        meta = entry.get('_meta', {})
        msg_idx = meta.get('msg_insn_idx')
        name_idx = meta.get('name_insn_idx')
        if msg_idx is None:
            warnings.append(f'{entry["id"]}: 缺少 _meta.msg_insn_idx')
            continue
        if msg_idx >= len(insns):
            warnings.append(f'{entry["id"]}: msg_insn_idx {msg_idx} 越界')
            continue

        # 替换 message
        try:
            msg_bytes = encode_cp932(entry['message'], full_width=True)
        except ValueError as e:
            warnings.append(f'{entry["id"]}: message 编码失败: {e}')
            continue

        # 检查目标确实是 TEXT 指令
        target = insns[msg_idx]
        if not (target[0] == 'OP' and target[2] == 0x01):
            warnings.append(
                f'{entry["id"]}: insn[{msg_idx}] 不是 TEXT 指令'
                f' (是 {target[0]}/{target[2] if target[0]=="OP" else "-"})'
            )
            continue
        insns[msg_idx][4][0] = msg_bytes

        # 替换 name (如有)
        if name_idx is not None and entry['name']:
            if name_idx >= len(insns):
                warnings.append(f'{entry["id"]}: name_insn_idx {name_idx} 越界')
            else:
                try:
                    # 角色名不做半角转全角 (短名字用全角会变奇怪)
                    name_bytes = encode_cp932(entry['name'], full_width=False)
                    name_target = insns[name_idx]
                    if (name_target[0] == 'OP' and name_target[2] == 0x01):
                        insns[name_idx][4][0] = name_bytes
                    else:
                        warnings.append(
                            f'{entry["id"]}: name insn[{name_idx}] 不是 TEXT'
                        )
                except ValueError as e:
                    warnings.append(f'{entry["id"]}: name 编码失败: {e}')

        replaced += 1

    # 第一遍 assemble, 构建 old → new 映射
    buf1, old_to_new, new_insns = assemble_with_offset_map(insns)

    # fixup 跳转
    unresolved = fixup_jumps(insns, old_to_new)
    if unresolved:
        for idx, op, old_tgt in unresolved:
            warnings.append(
                f'跳转 insn[{idx}] op 0x{op:02x} 目标 0x{old_tgt:x} 无法映射'
            )

    # 第二遍 assemble (I 字段固定 4 字节, 长度不变, 一次收敛)
    buf2, old_to_new2, _ = assemble_with_offset_map(insns)

    # 断言: 两次长度一致
    if len(buf1) != len(buf2):
        raise RuntimeError(
            f'FIXME: assemble 未收敛, len1={len(buf1)} len2={len(buf2)}'
        )
    # 断言: 两次映射一致 (跳转 fixup 没改变任何指令长度)
    if old_to_new != old_to_new2:
        raise RuntimeError('FIXME: fixup 后映射变了, 说明有变长的 I 参数')

    if verify_only:
        return replaced, warnings, None

    # 伪 LZSS 压缩 + 写文件
    compressed = lzss_compress_fake(buf2)
    if out_mes_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_mes_path)) or '.', exist_ok=True)
        with open(out_mes_path, 'wb') as f:
            f.write(compressed)

    return replaced, warnings, compressed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def cmd_single(orig, js, out):
    n, warnings, data = inject_one(orig, js, out)
    print(f'{orig} + {js} → {out}: 替换 {n} 条, 输出 {len(data)} 字节')
    if warnings:
        print(f'警告 ({len(warnings)} 条):')
        for w in warnings:
            print(f'  - {w}')


def cmd_batch(orig_dir, json_dir, out_dir):
    import shutil
    files = sorted(f for f in os.listdir(orig_dir) if f.upper().endswith('.MES'))
    os.makedirs(out_dir, exist_ok=True)
    total_replaced = 0
    all_warnings = []      # [(filename, warning_text), ...]
    copied_asis = []        # 无对应 JSON 的 MES, 原样拷贝
    failed = []             # 真正失败的
    for fn in files:
        stem = fn.rsplit('.', 1)[0]
        orig = os.path.join(orig_dir, fn)
        js = os.path.join(json_dir, stem + '.json')
        out = os.path.join(out_dir, fn)
        if not os.path.exists(js):
            # 无对应 JSON — 通常是该 MES 没有任何可翻译文本
            # (extract 阶段被跳过), 为保证 out_dir 是一套完整的替换集, 原样拷贝
            shutil.copyfile(orig, out)
            copied_asis.append(fn)
            continue
        try:
            n, warnings, _ = inject_one(orig, js, out)
            total_replaced += n
            for w in warnings:
                all_warnings.append((fn, w))
        except Exception as e:
            failed.append((fn, str(e)[:200]))
            continue

    injected_count = len(files) - len(failed) - len(copied_asis)
    print(f'\n=== inject 结果 ===')
    print(f'总文件: {len(files)}')
    print(f'  注入: {injected_count}')
    print(f'  原样拷贝 (无 JSON): {len(copied_asis)}')
    print(f'  失败: {len(failed)}')
    print(f'替换消息数: {total_replaced}')
    print(f'警告总数: {len(all_warnings)}')

    if all_warnings:
        print(f'\n--- 警告明细 ---')
        # 按文件分组显示
        from collections import defaultdict
        by_file = defaultdict(list)
        for fn, w in all_warnings:
            by_file[fn].append(w)
        for fn in sorted(by_file):
            ws = by_file[fn]
            print(f'  [{fn}] ({len(ws)} 条)')
            for w in ws:
                print(f'    - {w}')

        # 同时写一份日志文件到 out_dir, 方便离线查看
        log_path = os.path.join(out_dir, 'inject_warnings.log')
        with open(log_path, 'w', encoding='utf-8') as lf:
            lf.write(f'# AI5WIN V7 MES inject warnings\n')
            lf.write(f'# 总文件: {len(files)} '
                     f'(注入 {injected_count}, 原样拷贝 {len(copied_asis)}, 失败 {len(failed)})\n')
            lf.write(f'# 替换消息: {total_replaced}\n')
            lf.write(f'# 警告总数: {len(all_warnings)}\n\n')
            for fn in sorted(by_file):
                ws = by_file[fn]
                lf.write(f'[{fn}] ({len(ws)} 条)\n')
                for w in ws:
                    lf.write(f'  - {w}\n')
                lf.write('\n')
        print(f'\n警告日志已写入: {log_path}')

    if failed:
        print(f'\n失败 ({len(failed)}):')
        for fn, err in failed:
            print(f'  {fn}: {err}')


def cmd_verify(orig, js):
    """dry run: 不写文件, 但跑完整 pipeline 做 sanity check"""
    n, warnings, data = inject_one(orig, js, out_mes_path=None, verify_only=True)
    print(f'{orig} + {js}: 替换 {n} 条 (verify only)')
    if warnings:
        print(f'警告 ({len(warnings)} 条):')
        for w in warnings:
            print(f'  - {w}')


def main():
    ap = argparse.ArgumentParser(description='AI5WIN V7 GalTransl JSON → MES 回注')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('single', help='单文件注入')
    p1.add_argument('orig_mes')
    p1.add_argument('json')
    p1.add_argument('out_mes')

    p2 = sub.add_parser('batch', help='批量注入')
    p2.add_argument('orig_dir')
    p2.add_argument('json_dir')
    p2.add_argument('out_dir')

    p3 = sub.add_parser('verify', help='dry run (不写文件, 仅跑 pipeline)')
    p3.add_argument('orig_mes')
    p3.add_argument('json')

    args = ap.parse_args()
    if args.cmd == 'single':
        cmd_single(args.orig_mes, args.json, args.out_mes)
    elif args.cmd == 'batch':
        cmd_batch(args.orig_dir, args.json_dir, args.out_dir)
    elif args.cmd == 'verify':
        cmd_verify(args.orig_mes, args.json)


if __name__ == '__main__':
    main()