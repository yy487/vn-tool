#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HIMITSU ISF 脚本文本注入工具

输入:
    - 原始 .isf 目录 (提取时同一个目录)
    - 翻译后的 dump.json
    - 输出目录
输出:
    注入翻译文本的 .isf 到输出目录 (加密状态与 --encrypted 一致)

用法:
    # 原始目录是加密 .ISF (从 isf_arc unpack 直出), 输出也加密:
    python isf_inject.py mes/ dump.json mes_cn/ --encrypted

    # 原始目录已解密, 输出也是明文:
    python isf_inject.py mes/ dump.json mes_cn/

    # 额外做 round-trip 自检:
    python isf_inject.py mes/ dump.json mes_cn/ --encrypted --verify

注入策略:
    - message == ori 时使用 _raw 原始字节精确回填, 不依赖文本清洗逻辑
    - message != ori 时按翻译后 SJIS 编码注入, 保留 has_name_br 排版
    - 每个文件独立处理, 失败不影响其他文件
"""
import os, sys, json, argparse
from isf_script import (
    isf_decrypt, isf_encrypt, parse_script, build_script,
    sjis_encode, SUB_FIXED_LEN,
    decode_himitsu_text, encode_himitsu_text,
)

def _find_talk_payload_start(content: bytes):
    if not content: return None
    off = 1
    while off < len(content):
        cmd = content[off]; off += 1
        if cmd in SUB_FIXED_LEN:
            off += SUB_FIXED_LEN[cmd]
        elif cmd == 0xFF:
            return off
    return None

def apply_items(ops, items):
    for e in items:
        i = e['idx']; o = e['op']; kind = e['kind']
        op = ops[i]
        ori = e.get('ori', '')
        msg = e.get('message', ori)

        if kind == 'talk':
            pstart = _find_talk_payload_start(op['content'])
            if pstart is None: continue
            if msg == ori and '_raw' in e:
                new_payload = bytes.fromhex(e['_raw'])
            else:
                new_payload = encode_himitsu_text(msg)
            tail_zeros = e.get('_tail_zeros', 0)
            op['content'] = op['content'][:pstart] + new_payload + (b'\x00' * tail_zeros)
        elif kind == 'title':
            tail = bytes.fromhex(e.get('_tail', '00'))
            op['content'] = sjis_encode(msg) + tail
        elif kind == 'ui':
            p = e['prefix']
            tail = bytes.fromhex(e.get('_tail', '00'))
            op['content'] = op['content'][:p] + sjis_encode(msg) + tail
        elif kind == 'sys':
            p = e['prefix']
            tz = e.get('_tail_zeros', 1)
            op['content'] = op['content'][:p] + sjis_encode(msg) + (b'\x00' * tz)

def process_one(in_path: str, out_path: str, items: list, encrypted: bool):
    raw = open(in_path, 'rb').read()
    plain = isf_decrypt(raw) if encrypted else raw
    hl, vi, offs, ops, o2i = parse_script(plain)
    if items:
        apply_items(ops, items)
    rebuilt = build_script(hl, vi, offs, ops, o2i)
    out = isf_encrypt(rebuilt) if encrypted else rebuilt
    with open(out_path, 'wb') as f:
        f.write(out)
    return raw, out

def main():
    ap = argparse.ArgumentParser(description='HIMITSU ISF 文本注入')
    ap.add_argument('dir', help='原始 .isf 所在目录')
    ap.add_argument('json', help='翻译后的 JSON')
    ap.add_argument('out_dir', help='输出目录')
    ap.add_argument('--encrypted', action='store_true',
                    help='目录内 .isf 是加密的; 输出也加密')
    ap.add_argument('--verify', action='store_true',
                    help='注入后做 round-trip 自检: 未翻译条目应保持 bit-perfect')
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    # 加载 JSON, 失败则尝试清洗 + 逐条兜底
    data = None
    try:
        with open(args.json, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f'[!] JSON 加载失败: {e}')
        print(f'[!] 尝试自动清洗...')
        with open(args.json, 'rb') as f:
            raw = f.read().decode('utf-8', errors='replace')
        import re as _re
        # 1) 清除译文里误入的控制字符
        cleaned = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', raw)
        # 2) 修复行内字符串值里未转义的 "
        def fix_line(line):
            m = _re.match(r'(\s*"(?:ori|message|name)":\s*")(.*)("\s*,?\s*)$', line)
            if not m: return line
            prefix, body, suffix = m.group(1), m.group(2), m.group(3)
            body = body.replace('\\"', '\x00ESC\x00')
            body = body.replace('"', '\\"')
            body = body.replace('\x00ESC\x00', '\\"')
            return prefix + body + suffix
        cleaned = '\n'.join(fix_line(ln) for ln in cleaned.split('\n'))
        # 3) 修复所有非法的反斜杠转义
        #    JSON 合法: \" \\ \/ \b \f \n \r \t \uXXXX
        #    其他 \X (如 \x, \a, \慢 等) 全部变成 \\X
        def _fix_esc(m):
            nxt = m.group(1)
            if nxt in '"\\/bfnrt':
                return m.group(0)  # 合法, 保留
            if nxt == 'u':
                return m.group(0)  # \uXXXX 合法
            return '\\\\' + nxt  # 非法, 双倍反斜杠
        cleaned = _re.sub(r'\\(.)', _fix_esc, cleaned)
        try:
            data = json.loads(cleaned)
            print('[!] 自动清洗后加载成功')
        except json.JSONDecodeError as e2:
            ln = e2.lineno - 1
            ls = cleaned.split('\n')
            ctx = ls[ln] if 0 <= ln < len(ls) else ''
            print(f'[X] 仍失败 @line {e2.lineno} col {e2.colno}: {e2.msg}')
            print(f'    {ctx[:150]}')
            print(f'[X] 请手动修复后重试')
            return

    files = sorted(f for f in os.listdir(args.dir) if f.lower().endswith('.isf'))
    ok = 0; bad = 0
    rt_ok = 0; rt_bad = 0
    for name in files:
        in_p = os.path.join(args.dir, name)
        out_p = os.path.join(args.out_dir, name)
        items = data.get(name, [])
        try:
            raw, out = process_one(in_p, out_p, items, args.encrypted)
            ok += 1
            if args.verify:
                # 判断本文件是否全部未翻译 (message == ori)
                all_untouched = all(
                    e.get('message', e.get('ori', '')) == e.get('ori', '')
                    for e in items
                )
                if all_untouched:
                    if raw == out:
                        rt_ok += 1
                    else:
                        rt_bad += 1
                        for i in range(min(len(raw), len(out))):
                            if raw[i] != out[i]:
                                print(f'  [round-trip diff] {name} @0x{i:X}: '
                                      f'{raw[i]:02X} vs {out[i]:02X} '
                                      f'(len {len(raw)} → {len(out)})')
                                break
        except Exception as e:
            bad += 1
            print(f'  [X] {name}: {e}')

    print(f'[inject] {ok} 成功 / {bad} 失败 → {args.out_dir}')
    if args.verify:
        print(f'[verify] {rt_ok} 个未翻译文件 round-trip OK, {rt_bad} 失败')

if __name__ == '__main__':
    main()
