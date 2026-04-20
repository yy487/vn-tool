#!/usr/bin/env python3
"""
avg3217_extract.py — AVG3217 SEEN.TXT 文本提取

用法:
    python avg3217_extract.py SEEN.TXT -o seen.json
    python avg3217_extract.py SEEN.TXT -o seen.json --dump-stats

输出 JSON 格式 (GalTransl 兼容):
    [
      {
        "id": 0,
        "name": "说话人" (可选),
        "message": "对话内容",
        "_file": "SEEN100.TXT",
        "_op": 255,
        "_line": 0,
        "_text_off": 2441,
        "_orig_len": 25,
        "_orig_hex": "..."
      },
      ...
    ]
"""
import struct, json, sys, argparse, re
from avg3217_common import (
    pacl_unpack, pack_decompress,
    parse_tpc32, find_all_text_ops,
)


# AVG3217 对话的 name+body 格式:
#   text op 1:  FF + u32 line_name + 【说话人】\0
#   分隔字节:   通常 2B (op 0x02 sub=3), 偶见 4B
#   text op 2:  FF + u32 line_body + 正文\0
# 所以判定方式: 当前 text op 解码后匹配 "^【([^】]+)】$", 下一条 text op
# 的 op_off 和当前 \0 位置的 gap <= MAX_NAME_BODY_GAP 字节, 就认为配对.
SPEAKER_ONLY_RE = re.compile(r'^【([^】]+)】$')
MAX_NAME_BODY_GAP = 8  # 经验值: 实际 gap=2 (02 03) 或 gap=4, 留余量


import re as _re
_PLAYER_REF_RE = _re.compile(r'＊[Ａ-Ｚ]')
_EMPTY_SPEAKER_RE = _re.compile(r'【】')


def _annotate_placeholders(entry):
    """扫 name/message 里的占位符, 加 _has_player_ref 和 _has_empty_speaker 标记.
    
    AVG3217 里两个字面占位符 (都由 VM 渲染层处理, 字节码里是字面 SJIS):
      ＊Ａ / ＊Ｂ / ＊Ｃ ... — 玩家输入的自定义姓/名, 游戏运行时替换
      【】 — 空说话人标签, 游戏显示时不渲染 (常见于独白/信件)
    
    翻译者必须保留这两种占位符的原样字符, 不能删除或改写.
    """
    txt = entry.get('message', '') + entry.get('name', '')
    if _PLAYER_REF_RE.search(txt):
        entry['_has_player_ref'] = True
    if _EMPTY_SPEAKER_RE.search(entry.get('message', '')):
        entry['_has_empty_speaker'] = True


def extract_one_file(fname, plain, gid_start):
    """处理单个 TPC32 文件. 返回 (entries, n_paired, gid_end)"""
    try:
        info = parse_tpc32(plain)
    except (AssertionError, struct.error):
        return [], 0, gid_start
    
    # 没有 e 子脚本也没文本, 跳过
    if info['metadata']['n_e_scripts'] == 0:
        return [], 0, gid_start
    
    texts = find_all_text_ops(plain, info)
    
    entries = []
    gid = gid_start
    n_paired = 0
    i = 0
    while i < len(texts):
        t = texts[i]
        sjis = bytes(plain[t['text_off']:t['text_off']+t['text_len']])
        try:
            msg = sjis.decode('cp932')
        except UnicodeDecodeError:
            msg = sjis.decode('cp932', errors='replace')
        
        entry = {'id': gid}
        paired = False
        
        # 配对模式: 当前 text 是 "【name】" (SPEAKER_ONLY), 下一条 text op 紧跟
        # (gap <= MAX_NAME_BODY_GAP, 通常 2 字节 = op 0x02 sub=3; 偶见 4 字节)
        # 两条 text op 必须在**同一子脚本**内才能配对
        mname = SPEAKER_ONLY_RE.match(msg)
        if mname and i + 1 < len(texts):
            cur_end = t['text_off'] + t['text_len'] + 1
            t2 = texts[i+1]
            # 必须同一子脚本
            same_sub = (t.get('sub_name') == t2.get('sub_name'))
            gap = t2['off'] - cur_end
            if same_sub and 0 <= gap <= MAX_NAME_BODY_GAP:
                next_sjis = bytes(plain[t2['text_off']:t2['text_off']+t2['text_len']])
                try:
                    next_msg = next_sjis.decode('cp932')
                except UnicodeDecodeError:
                    next_msg = next_sjis.decode('cp932', errors='replace')
                if not SPEAKER_ONLY_RE.match(next_msg):
                    entry['name'] = mname.group(1)
                    entry['message'] = next_msg
                    entry['_file'] = fname
                    entry['_op'] = t['op']
                    entry['_line'] = t['line']
                    entry['_text_off'] = t['text_off']
                    entry['_orig_len'] = t['text_len']
                    entry['_orig_hex'] = sjis.hex()
                    entry['_sub'] = t.get('sub_name', '')
                    entry['_body_op'] = t2['op']
                    entry['_body_line'] = t2['line']
                    entry['_body_text_off'] = t2['text_off']
                    entry['_body_orig_len'] = t2['text_len']
                    entry['_body_orig_hex'] = next_sjis.hex()
                    entry['_gap'] = gap
                    _annotate_placeholders(entry)
                    entries.append(entry); gid += 1; n_paired += 1
                    i += 2
                    paired = True
        
        if not paired:
            entry['message'] = msg
            entry['_file'] = fname
            entry['_op'] = t['op']
            entry['_line'] = t['line']
            entry['_text_off'] = t['text_off']
            entry['_orig_len'] = t['text_len']
            entry['_orig_hex'] = sjis.hex()
            entry['_sub'] = t.get('sub_name', '')
            _annotate_placeholders(entry)
            entries.append(entry); gid += 1
            i += 1
    
    return entries, n_paired, gid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='SEEN.TXT 文件路径')
    ap.add_argument('-o', '--output', default='seen.json', help='输出 JSON')
    ap.add_argument('--dump-stats', action='store_true', help='打印每个子文件的统计')
    ap.add_argument('--skip-empty', action='store_true', default=True,
                    help='跳过 code_count=0 的文件 (默认开启)')
    args = ap.parse_args()
    
    raw = open(args.input, 'rb').read()
    items = pacl_unpack(raw)
    print(f'[*] PACL: {len(items)} 个文件', file=sys.stderr)
    
    all_entries = []
    gid = 0
    total_paired = 0
    n_cc0 = 0
    n_cc_pos = 0
    per_file_counts = []
    
    for name, csize, ucsize, flag, blk in items:
        try:
            plain = pack_decompress(blk)
        except Exception as ex:
            print(f'[!] {name} 解压失败: {ex}', file=sys.stderr)
            continue
        if len(plain) != ucsize:
            print(f'[!] {name} 解压大小不符: {len(plain)} vs {ucsize}', file=sys.stderr)
        
        try:
            info = parse_tpc32(plain)
        except (AssertionError, struct.error):
            print(f'[!] {name} 非 TPC32', file=sys.stderr)
            continue
        
        n_e = info['metadata']['n_e_scripts']
        if n_e == 0:
            n_cc0 += 1
            if args.dump_stats:
                per_file_counts.append((name, 0, 0, 'n_e_scripts=0 跳过'))
            continue
        n_cc_pos += 1
        
        entries, n_paired, gid = extract_one_file(name, plain, gid)
        all_entries.extend(entries)
        total_paired += n_paired
        if args.dump_stats:
            per_file_counts.append((name, n_e, len(entries), ''))
    
    print(f'[*] 有 e-子脚本的文件: {n_cc_pos}, 空 (n_e=0, 跳过): {n_cc0}', file=sys.stderr)
    print(f'[*] 文本: {len(all_entries)} (name+body 配对: {total_paired})', file=sys.stderr)
    
    if args.dump_stats:
        print(f'\n[*] 逐文件统计:', file=sys.stderr)
        for name, n_e, cnt, note in per_file_counts:
            if n_e > 0:
                print(f'  {name:15s} n_e={n_e:2d}  entries={cnt:4d} {note}', file=sys.stderr)
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(all_entries, f, ensure_ascii=False, indent=2)
    print(f'[*] 写入 {args.output}', file=sys.stderr)


if __name__ == '__main__':
    main()
