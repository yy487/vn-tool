#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fizz SPT 注入器 (cmd=1 / Arg_Type0)

用法:
  # 1. 默认输出解密后的 .bin, 让 fizz_spt_cryptor 独立加密回 SPT (推荐)
  fizz_spt_extract.py extract fd.spt fd.tl.json
  #   ... 翻译 fd.tl.json ...
  fizz_spt_inject.py fd.spt fd.tl.json fd.bin
  fizz_spt_cryptor.py encrypt fd.bin fd_cn.spt --ref fd.spt

  # 2. 或者一步到位, 直接输出加密后的 SPT (需 --encrypt --ref 原 SPT)
  fizz_spt_inject.py fd.spt fd.tl.json fd_cn.spt --encrypt

  # 批量
  fizz_spt_inject.py --batch spt_dir/ json_dir/ out_dir/ [--encrypt]

选项:
  --varlen   变长重建 (sl0 可变, SPT 无跳转表所以安全). 默认等长.
  --enc cp932  字符编码 cp932 (默认, 日文/日繁) 或 gbk (简体中文)
  --encrypt  输出加密的 SPT (而非解密的 bin), 使用源 SPT 的头参数

---- token 约定 (与 extract 对齐) ----
  '<br>'      nType=13 段落终止
  '<rb>'      nType=8  注音 begin (复用原 nP0/nP1)
  '<re>'      nType=9  注音 end   (复用原 nP0/nP1)
  '<t{NN}>'   nType=NN 控制 entry (复用原 nP0/nP1)
  '<x{HHHH}>' nType=7 不可 CP932 解码字符回写, nP1=HHHH

---- 注入模式 ----
  等长 (equal-length): 仅改 sl0 个 Char_Entry 的字节, 文件其它部分不动.
                       token 数必须 ≤ sl0, 不足末尾补全角空格 '　'.
  变长 (varlen):       重建整个 byte stream, sl0 可任意. 安全性靠 SPT 无跳转表.
"""
import sys, struct, json, re
from pathlib import Path
from fizz_spt_cryptor import spt_decrypt, spt_encrypt, detect_keys

# ============================================================================
# Token 解析
# ============================================================================

TOKEN_RE = re.compile(r'(<br>|<rb>|<re>|<t\d+>|<x[0-9a-fA-F]+>)')
PAD_NP1 = 0x40 | (0x81 << 8)  # '　' 全角空格 CP932 BE: b1=81 b2=40

ENCODING = 'cp932'  # 由 main 设置: 'cp932' (纯日文/日繁) / 'gbk' (简体中文, 自动 CP932 fallback)

def parse_message(msg):
    out = []
    i = 0
    while i < len(msg):
        m = TOKEN_RE.match(msg, i)
        if m:
            out.append(('s', m.group(1))); i = m.end()
        else:
            out.append(('c', msg[i])); i += 1
    return out

def char_to_np1(ch):
    """单字符 → BE 编码 nP1.
    ENCODING='cp932': 仅 CP932
    ENCODING='gbk':   先 CP932 (保留日文符号如 ♪〜♥), 失败再 GBK
    """
    if ENCODING == 'gbk':
        try:
            b = ch.encode('cp932')
        except UnicodeEncodeError:
            try:
                b = ch.encode('gbk')
            except UnicodeEncodeError:
                raise ValueError(f"字符 {ch!r} 既不能 CP932 也不能 GBK 编码")
    else:
        try:
            b = ch.encode('cp932')
        except UnicodeEncodeError:
            raise ValueError(f"字符 {ch!r} 无法 CP932 编码 (简体字请加 --enc gbk)")
    if len(b) == 1:
        return b[0]
    if len(b) == 2:
        return b[0] | (b[1] << 8)
    raise ValueError(f"字符 {ch!r} 编码长度 {len(b)} 异常")

def tokens_to_entries(tokens, orig_entries):
    """token → [(nType, nP0, nP1)]. 控制 token 按顺序复用原 nP0/nP1."""
    # 按 nType 分组收集原始非-7/13 entry 的 (nP0, nP1)
    ctrl_pool = {}
    for nt, p0, p1 in orig_entries:
        if nt not in (7, 13):
            ctrl_pool.setdefault(nt, []).append((p0, p1))
    ctrl_idx = {nt: 0 for nt in ctrl_pool}

    def take_ctrl(nt):
        if nt in ctrl_pool and ctrl_idx[nt] < len(ctrl_pool[nt]):
            v = ctrl_pool[nt][ctrl_idx[nt]]; ctrl_idx[nt] += 1
            return v
        return (0, 0)

    out = []
    for kind, val in tokens:
        if kind == 'c':
            out.append((7, 0, char_to_np1(val)))
        elif val == '<br>':
            out.append((13, 0, 0))
        elif val == '<rb>':
            p0, p1 = take_ctrl(8); out.append((8, p0, p1))
        elif val == '<re>':
            p0, p1 = take_ctrl(9); out.append((9, p0, p1))
        elif val.startswith('<t'):
            nt = int(val[2:-1]); p0, p1 = take_ctrl(nt); out.append((nt, p0, p1))
        elif val.startswith('<x'):
            out.append((7, 0, int(val[2:-1], 16)))
        else:
            raise ValueError(f"未知 token: {val!r}")
    return out

# ============================================================================
# 注入模式
# ============================================================================

def inject_equal(dec, e):
    """等长替换. 修改 dec (bytearray) in-place. 错误返回 error str, 成功返回 None."""
    off, sl0 = e['_off'], e['_sl0']
    entries_off = off + 36 + 28
    orig = [struct.unpack_from('<III', dec, entries_off + i * 12) for i in range(sl0)]

    tokens = parse_message(e['message'])
    new = tokens_to_entries(tokens, orig)

    if len(new) > sl0:
        return f"@0x{off:x} token 数 {len(new)} > 原 sl0 {sl0} (建议 --varlen)"

    # 补齐: 在末尾控制 token 之前插入全角空格
    if len(new) < sl0:
        ip = len(new)
        while ip > 0 and new[ip - 1][0] in (13, 8, 9):
            ip -= 1
        for _ in range(sl0 - len(new)):
            new.insert(ip, (7, 0, PAD_NP1))

    for i, (nt, p0, p1) in enumerate(new):
        struct.pack_into('<III', dec, entries_off + i * 12, nt, p0, p1)
    return None

def code_total_size(dec, off):
    a = off + 36
    sl0, sl1, sl2 = struct.unpack_from('<III', dec, a + 16)
    sz = 36 + 28 + sl0 * 12
    if sl1 > 0: sz += sl1 + 1
    if sl2 > 0: sz += sl2 + 1
    return sz

def inject_varlen(dec, entries):
    """变长重建. 返回新 bytes. 依赖 SPT 无跳转表的事实."""
    entries = sorted(entries, key=lambda x: x['_off'])
    out = bytearray()
    cursor = 0
    for e in entries:
        off, sl0 = e['_off'], e['_sl0']
        a = off + 36
        nrSeq, ndSeq, un2, vfSeq, _sl0, sl1, sl2 = struct.unpack_from('<IIIIIII', dec, a)
        if _sl0 != sl0:
            raise ValueError(f"@0x{off:x} 文件 sl0={_sl0} ≠ JSON _sl0={sl0}")
        entries_off = a + 28
        orig = [struct.unpack_from('<III', dec, entries_off + i * 12) for i in range(sl0)]
        tokens = parse_message(e['message'])
        new = tokens_to_entries(tokens, orig)

        out += dec[cursor:off]                                            # 前置区块
        out += dec[off:a]                                                 # 原 Code header (36B)
        out += struct.pack('<IIIIIII', nrSeq, ndSeq, un2, vfSeq,
                           len(new), sl1, sl2)                            # Arg_Type0 header (sl0 更新)
        for nt, p0, p1 in new:
            out += struct.pack('<III', nt, p0, p1)                        # 新 entries
        out += dec[entries_off + sl0 * 12: off + code_total_size(dec, off)]  # sl1/sl2 payload
        cursor = off + code_total_size(dec, off)
    out += dec[cursor:]
    return bytes(out)

# ============================================================================
# 高层流程
# ============================================================================

def do_inject_one(spt_path, json_path, out_path, varlen=False, encrypt=False, verbose=True):
    raw = open(spt_path, 'rb').read()
    dec = bytearray(spt_decrypt(raw))
    tl = json.load(open(json_path, 'r', encoding='utf-8'))

    if varlen:
        new_bin = inject_varlen(dec, tl)
        mode = 'varlen'
        detail = f'{len(dec)} -> {len(new_bin)}'
    else:
        errors = []; ok = 0
        for e in tl:
            err = inject_equal(dec, e)
            if err: errors.append(err)
            else: ok += 1
        if errors:
            if verbose:
                for x in errors[:10]: print('  !', x, file=sys.stderr)
                if len(errors) > 10:
                    print(f'  ... and {len(errors) - 10} more', file=sys.stderr)
            raise ValueError(f"{len(errors)} 条等长注入失败, 尝试 --varlen")
        new_bin = bytes(dec)
        mode = 'equal'
        detail = f'{ok}/{len(tl)}'

    if encrypt:
        start, dtype, un0, un1 = detect_keys(raw)
        final = spt_encrypt(new_bin, start, dtype, un0, un1)
    else:
        final = new_bin

    Path(out_path).write_bytes(final)
    if verbose:
        tag = 'SPT' if encrypt else 'bin'
        print(f'[{mode}/{tag}] {spt_path} + {json_path} -> {out_path} ({detail})',
              file=sys.stderr)

def do_inject_batch(spt_dir, json_dir, out_dir, varlen=False, encrypt=False):
    import shutil
    spt_dir, json_dir, out_dir = Path(spt_dir), Path(json_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(spt_dir.glob('*.spt'))
    ok = 0; fail = 0; copied = 0
    for spt in files:
        tl = json_dir / (spt.stem + '.tl.json')
        if not tl.exists():
            # 没对应 JSON: 原封不动复制/转换源 SPT
            if encrypt:
                # 目标是加密 SPT, 直接 cp
                out = out_dir / spt.name
                shutil.copyfile(spt, out)
            else:
                # 目标是 .bin (解密态)
                out = out_dir / (spt.stem + '.bin')
                out.write_bytes(spt_decrypt(spt.read_bytes()))
            copied += 1
            print(f'  [copy] {spt.name} (no .tl.json)', file=sys.stderr)
            continue
        ext = '.spt' if encrypt else '.bin'
        out = out_dir / (spt.stem + ext)
        try:
            do_inject_one(spt, tl, out, varlen=varlen, encrypt=encrypt, verbose=False)
            ok += 1
            print(f'  [ok] {spt.name}', file=sys.stderr)
        except Exception as ex:
            fail += 1
            print(f'  [fail] {spt.name}: {ex}', file=sys.stderr)
    print(f'[batch] {ok} injected, {copied} copied (no .tl.json), {fail} failed', file=sys.stderr)

# ============================================================================
# CLI
# ============================================================================

def main():
    import argparse
    ap = argparse.ArgumentParser(description='Fizz SPT inject')
    ap.add_argument('input_spt', help='源 SPT 文件 (或批量模式下的源 SPT 目录)')
    ap.add_argument('input_json', help='翻译 JSON (或批量模式下的 JSON 目录)')
    ap.add_argument('output', help='输出路径 (默认 .bin 需用 cryptor 加密; --encrypt 则输出 SPT)')
    ap.add_argument('--varlen', action='store_true', help='变长重建 (sl0 可变)')
    ap.add_argument('--encrypt', action='store_true', help='直接输出加密 SPT (用源 SPT 头参数)')
    ap.add_argument('--enc', choices=['cp932', 'gbk'], default='cp932',
                    help='字符编码 (默认 cp932 日文/日繁, gbk 用于简体中文)')
    ap.add_argument('--gbk', action='store_true',
                    help='(旧 alias) 等价于 --enc gbk')
    ap.add_argument('--batch', action='store_true', help='批量: 3 个参数解读为 spt_dir / json_dir / out_dir')
    args = ap.parse_args()

    global ENCODING
    ENCODING = 'gbk' if args.gbk else args.enc

    if args.batch:
        do_inject_batch(args.input_spt, args.input_json, args.output,
                        varlen=args.varlen, encrypt=args.encrypt)
    else:
        do_inject_one(args.input_spt, args.input_json, args.output,
                      varlen=args.varlen, encrypt=args.encrypt)

if __name__ == '__main__':
    main()
