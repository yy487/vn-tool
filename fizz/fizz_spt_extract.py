#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fizz SPT 对话提取器 (cmd=1 / Arg_Type0)

用法:
  fizz_spt_extract.py scan    <in.spt>
  fizz_spt_extract.py extract <in.spt> <out.tl.json>
  fizz_spt_extract.py batch   <spt_dir> <json_dir>

---- 引擎结构 ----

Code header (36B):
  cmd, v1, v2, v3, v4, seq, c1, c2, c3  (每个 u32)
  cmd=1 对话 Code 的前 36B 高度规整: v1..v4 = c1..c3 = 0

Arg_Type0 (cmd=1 时紧随 Code header, 28B header + sl0×12B Char_Entry):
  +0   NameReallySeq    讲话者真实ID (0xFFFFFFFF = 旁白)
  +4   NameDisplaySeq   讲话者显示ID
  +8   Un2
  +12  VoiceFileSeq     语音编号
  +16  sl0              Char_Entry 数量
  +20  sl1 / +24 sl2    可选 raw str 长度

Char_Entry (12B):
  +0  nType   7=字符, 13=段落终止, 8/9=注音 begin/end, 5/其它=控制
  +4  nP0     控制 entry 的状态字 (例 nType=8 注音 nP0 非零), inject 必须保留
  +8  nP1     nType=7 时 低 2B = CP932 字节 (b1=低字节, b2=高字节)

---- token 约定 (与 inject 对齐) ----
  '<br>'      nType=13 段落终止 (用 <br> 而非 \\n 避免与文本中的 \\n 单字符冲突)
  '<rb>'      nType=8  注音 begin
  '<re>'      nType=9  注音 end
  '<t{NN}>'   nType=NN 其它控制 (注入时复用原 nP0/nP1)
  '<x{HHHH}>' nType=7 但 nP1 不可 CP932 解码, 回写时原样保留

---- 识别策略 ----
magic = b'\\x01' + 19B 全 0, 对应 cmd=1 + v1..v4 全 0
严格模式: magic 匹配后, 再验证 +24..36 = 12B 全 0 (c1c2c3)
  → 在 fd_fuduki 上实测 0 假阳性, 1672 条真对话全部命中
"""
import sys, struct, json
from pathlib import Path
from fizz_spt_cryptor import spt_decrypt
from fizz_spt_global import load_name_dict

# magic: cmd + v1..v4 (20B)
MAGIC = b'\x01\x00\x00\x00' + b'\x00' * 16

# ============================================================================
# 解码 / 识别
# ============================================================================

def char_entry_to_str(entries):
    """entry 列表 → 可逆 token 字符串."""
    out = []
    for nType, _p0, nP1 in entries:
        if nType == 7:
            b1 = nP1 & 0xff
            b2 = (nP1 >> 8) & 0xff
            try:
                if b2 == 0:
                    out.append(bytes([b1]).decode('cp932'))
                else:
                    out.append(bytes([b1, b2]).decode('cp932'))
            except UnicodeDecodeError:
                out.append(f'<x{nP1:04x}>')
        elif nType == 13:
            out.append('<br>')
        elif nType == 8:
            out.append('<rb>')
        elif nType == 9:
            out.append('<re>')
        else:
            out.append(f'<t{nType}>')
    return ''.join(out)

def parse_dialog_at(dec, off):
    """假设 dec[off:off+20] == MAGIC, 解析后续 Arg_Type0. 失败返回 None."""
    if struct.unpack_from('<III', dec, off + 24) != (0, 0, 0):
        return None
    a = off + 36
    if a + 28 > len(dec):
        return None
    nrSeq, ndSeq, un2, vfSeq, sl0, sl1, sl2 = struct.unpack_from('<IIIIIII', dec, a)
    if sl0 == 0 and sl1 == 0 and sl2 == 0:
        return None
    if sl0 > 1000 or sl1 > 4096 or sl2 > 4096:
        return None
    entries_off = a + 28
    if entries_off + sl0 * 12 > len(dec):
        return None
    entries = [struct.unpack_from('<III', dec, entries_off + i * 12) for i in range(sl0)]
    return {
        'off': off,
        'nrSeq': nrSeq, 'ndSeq': ndSeq, 'un2': un2, 'vfSeq': vfSeq,
        'sl0': sl0, 'sl1': sl1, 'sl2': sl2,
        'entries': entries,
        'text': char_entry_to_str(entries),
    }

def extract_all_dialogs(spt_path):
    raw = open(spt_path, 'rb').read()
    dec = spt_decrypt(raw)  # 默认 make_readable=False, 保留真头
    results = []
    pos = 0
    while True:
        idx = dec.find(MAGIC, pos)
        if idx < 0:
            break
        r = parse_dialog_at(dec, idx)
        if r:
            # 跳过整个 Code 防止 sl1/sl2 payload 里再次命中 magic
            sz = 36 + 28 + r['sl0'] * 12
            if r['sl1'] > 0: sz += r['sl1'] + 1
            if r['sl2'] > 0: sz += r['sl2'] + 1
            results.append(r)
            pos = idx + sz
        else:
            pos = idx + 1
    return results

# ============================================================================
# CLI
# ============================================================================

def dialog_to_json_entry(r, name_dict=None):
    name = ''
    if name_dict is not None:
        # nameSeq = 0xFFFFFFFF → 旁白, name 留空
        if r['nrSeq'] in name_dict:
            name = name_dict[r['nrSeq']]
    return {
        'name': name,
        'nameSeq': r['nrSeq'],
        'voiceSeq': r['vfSeq'],
        'message': r['text'],
        'src_msg': r['text'],
        '_off': r['off'],
        '_sl0': r['sl0'],
    }

def cli_scan(args):
    results = extract_all_dialogs(args.input)
    print(f'Found {len(results)} dialogs in {args.input}', file=sys.stderr)
    for r in results[:30]:
        print(f"  @0x{r['off']:x} nr={r['nrSeq']} vf={r['vfSeq']} sl0={r['sl0']}: {r['text']}")
    if len(results) > 30:
        print(f'... (showing first 30 of {len(results)})')

def cli_extract(args):
    results = extract_all_dialogs(args.input)
    name_dict = load_name_dict(args.global_dat) if args.global_dat else None
    out = [dialog_to_json_entry(r, name_dict) for r in results]
    Path(args.output).write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'[extract] {args.input} -> {args.output} ({len(out)} entries)', file=sys.stderr)

def cli_batch(args):
    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name_dict = load_name_dict(args.global_dat) if args.global_dat else None
    files = sorted(in_dir.glob('*.spt'))
    total = 0; skipped = 0
    for spt in files:
        results = extract_all_dialogs(spt)
        if not results:
            skipped += 1
            print(f'  [skip] {spt.name}: 0 dialogs', file=sys.stderr)
            continue
        out = [dialog_to_json_entry(r, name_dict) for r in results]
        out_path = out_dir / (spt.stem + '.tl.json')
        out_path.write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
        total += len(out)
        print(f'  {spt.name}: {len(out)} dialogs', file=sys.stderr)
    print(f'[batch] {len(files)} files, {len(files)-skipped} written, {skipped} skipped (empty), {total} total dialogs', file=sys.stderr)

def main():
    import argparse
    ap = argparse.ArgumentParser(description='Fizz SPT extract (cmd=1 dialogs)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('scan'); p.add_argument('input'); p.set_defaults(func=cli_scan)
    p = sub.add_parser('extract')
    p.add_argument('input')
    p.add_argument('output')
    p.add_argument('--global', dest='global_dat', help='global.dat 路径 (填充 name 字段)')
    p.set_defaults(func=cli_extract)
    p = sub.add_parser('batch')
    p.add_argument('input_dir')
    p.add_argument('output_dir')
    p.add_argument('--global', dest='global_dat', help='global.dat 路径 (填充 name 字段)')
    p.set_defaults(func=cli_batch)

    args = ap.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
