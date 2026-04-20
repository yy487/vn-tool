#!/usr/bin/env python3
"""
hcb_text.py — HCB脚本文本提取工具
引擎: アトリエかぐや/ωstar 自研引擎 (v26)
游戏: クラ☆クラ CLASSY☆CRANBERRY'S 等

用法:
  python hcb_text.py extract input.hcb [-o output.json] [-f json|txt]
  python hcb_text.py info    input.hcb
"""

import struct, os, argparse, json
from collections import Counter

def parse_header(data):
    hdr_off = struct.unpack_from('<I', data, 0)[0]
    pos = hdr_off
    info = {'header_offset': hdr_off}
    info['entry_point'] = struct.unpack_from('<I', data, pos)[0]; pos += 4
    info['count_a'] = struct.unpack_from('<h', data, pos)[0]; pos += 2
    info['count_b'] = struct.unpack_from('<h', data, pos)[0]; pos += 2
    res_table = [(640,480),(800,600),(1024,768),(1280,960),(1600,1200),(640,480),
                 (1024,576),(1024,640),(1280,720),(1280,800),(1440,810),(1440,900),
                 (1680,945),(1680,1050),(1920,1080),(1920,1200)]
    res_idx = data[pos]; pos += 1
    info['resolution'] = res_table[res_idx] if res_idx < 16 else (0, 0)
    pos += 1
    title_len = data[pos]; pos += 1
    info['title'] = data[pos:pos+title_len].rstrip(b'\x00').decode('cp932', errors='replace') if title_len else ''
    pos += title_len
    cmd_count = struct.unpack_from('<h', data, pos)[0]; pos += 2
    commands = []
    for _ in range(cmd_count):
        typ = struct.unpack_from('<b', data, pos)[0]
        nl = data[pos+1]; name = data[pos+2:pos+2+nl].rstrip(b'\x00').decode('ascii', errors='replace')
        commands.append((typ, name)); pos += 2 + nl
    info['commands'] = commands
    return info

def build_name_funcs(data):
    nf = {}
    i = 4
    while i < 0x2000:
        if data[i:i+4] == b'\x01\x03\x00\x0c':
            j = i + 5; names = []
            while j < i + 300:
                if data[j] == 0x0e:
                    sl = data[j+1]
                    if 2 <= sl <= 50:
                        try:
                            n = data[j+2:j+2+sl-1].decode('cp932')
                            if n.encode('cp932') + b'\x00' == data[j+2:j+2+sl] and n.startswith('【'):
                                names.append(n)
                        except: pass
                    j += 2 + sl
                elif data[j:j+2] == b'\x04\x04': break
                else: j += 1
            if names:
                real = [n for n in names if '？' not in n]
                nf[i] = real[-1] if real else names[-1]
        i += 1
    return nf

def find_special_funcs(data, bytecode_end):
    nf = build_name_funcs(data)
    ct = Counter()
    i = 4
    while i < bytecode_end - 1:
        op = data[i]
        if op == 0x0e: i += 2 + data[i+1]
        elif op in (0x02, 0x06, 0x07, 0x0a):
            if op == 0x02:
                a = struct.unpack_from('<I', data, i+1)[0]
                if a < bytecode_end: ct[a] += 1
            i += 5
        elif op in (0x0b, 0x0f, 0x03, 0x15, 0x11, 0x12, 0x13): i += 3
        elif op in (0x0c, 0x10, 0x16): i += 2
        else: i += 1
    ranked = [(a, c) for a, c in ct.most_common(10) if a not in nf]
    return (ranked[0][0] if len(ranked)>0 else None,
            ranked[1][0] if len(ranked)>1 else None,
            ranked[2][0] if len(ranked)>2 else None)

def _classify(text):
    if text.startswith('【') and '】' in text: return 'name'
    has_jp = any(ord(c) > 0x3000 for c in text)
    if '/' in text and not has_jp: return 'resource'
    hk = any(0x3040 <= ord(c) <= 0x30FF for c in text)
    hj = any(0x4E00 <= ord(c) <= 0x9FFF for c in text)
    if any(c in text for c in '。？！') and len(text) > 3: return 'dialogue'
    if (hk or hj) and len(text) > 2:
        if text[0] in '「『（' or any(c in text for c in '…～♪、') or len(text) > 5:
            return 'dialogue'
        return 'scene'
    if text.replace('_','').replace('-','').isalnum(): return 'label'
    return 'other'

def extract_with_speakers(data, bytecode_end):
    nf = build_name_funcs(data)
    wf, cf, _ = find_special_funcs(data, bytecode_end)
    results = []; speaker = None; i = 4
    while i < bytecode_end - 1:
        op = data[i]
        if op == 0x02:
            if i + 5 > bytecode_end: break
            addr = struct.unpack_from('<I', data, i+1)[0]
            if addr in nf: speaker = nf[addr]
            elif addr == cf: speaker = None
            i += 5; continue
        if op == 0x0e:
            sl = data[i+1]
            if 2 <= sl <= 255:
                sb = data[i+2:i+2+sl]
                if sb[-1] == 0:
                    try:
                        t = sb[:-1].decode('cp932')
                        if t.encode('cp932') + b'\x00' == sb and len(t) >= 1:
                            results.append((i, sl, t, speaker, _classify(t)))
                    except: pass
            i += 2 + sl; continue
        if op in (0x06,0x07,0x0a): i += 5
        elif op in (0x0b,0x0f,0x03,0x15,0x11,0x12,0x13): i += 3
        elif op in (0x0c,0x10,0x16): i += 2
        else: i += 1
    return results

def _is_dialogue_text(text, offset, cat):
    if offset < 0x0C0000:
        return False
    if cat in ('label', 'resource'):
        return False
    if text.startswith('_'):
        return False
    if '_吹出' in text:
        return False
    if any(ord(c) < 0x20 and c not in '\n\r\t' for c in text):
        return False
    has_jp = any(ord(c) > 0x3000 for c in text)
    has_kana = any(0x3040 <= ord(c) <= 0x30FF for c in text)
    has_kanji = any(0x4E00 <= ord(c) <= 0x9FFF for c in text)
    if not (has_jp or has_kana or has_kanji or text.startswith('「')):
        return False
    return True

def extract(args):
    with open(args.input, 'rb') as f: data = f.read()
    info = parse_header(data); be = info['header_offset']
    nf = build_name_funcs(data)
    wf, cf, nrf = find_special_funcs(data, be)
    print(f"文件大小: {len(data)} bytes | 标题: {info['title']} | 分辨率: {info['resolution'][0]}x{info['resolution'][1]}")
    print(f"命令数: {len(info['commands'])} | 角色: {len(nf)} | 翻页: 0x{wf:X} | 清屏: 0x{cf:X}")
    all_s = extract_with_speakers(data, be)
    print(f"扫描到 {len(all_s)} 个字符串")

    seen = set(); tr = []
    for off, ol, t, spk, cat in all_s:
        if off in seen: continue
        if _is_dialogue_text(t, off, cat):
            seen.add(off); tr.append((off, ol, t, spk, cat))
    print(f"有效对话: {len(tr)}")

    fmt = getattr(args, 'format', 'json')
    if fmt == 'txt':
        out = args.output or os.path.splitext(args.input)[0] + '_text.txt'
        with open(out, 'w', encoding='utf-8') as f:
            f.write(f"# HCB Text Export | {os.path.basename(args.input)} | {info['title']} | {len(tr)} strings\n")
            f.write(f"# offset\\torig_len\\tspeaker\\tcategory\\toriginal\\ttranslation\n#\n")
            for off, ol, t, spk, cat in tr:
                s = spk or ''; e = t.replace('\\','\\\\').replace('\n','\\n').replace('\r','\\r').replace('\t','\\t')
                f.write(f"0x{off:06X}\t{ol}\t{s}\t{cat}\t{e}\t{e}\n")
    else:
        out = args.output or os.path.splitext(args.input)[0] + '.json'
        if not out.endswith('.json'): out += '.json'
        entries = []
        for idx, (off, ol, t, spk, cat) in enumerate(tr):
            entries.append({
                "name": spk if spk else None,
                "message": t,
                "message_id": idx,
                "max_bytes": ol - 1
            })
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"输出: {out}")

def show_info(args):
    with open(args.input, 'rb') as f: d = f.read()
    info = parse_header(d); be = info['header_offset']
    nf = build_name_funcs(d); wf, cf, nrf = find_special_funcs(d, be)
    print(f"文件: {len(d)} bytes | 标题: {info['title']} | 分辨率: {info['resolution'][0]}x{info['resolution'][1]}")
    print(f"入口: 0x{info['entry_point']:X} | labels: {info['count_a']}+{info['count_b']} | 命令: {len(info['commands'])}")
    print(f"\n角色({len(nf)}):")
    for a in sorted(nf): print(f"  0x{a:04X} → {nf[a]}")
    print(f"\n特殊函数: 翻页=0x{wf:X} 清屏=0x{cf:X}" + (f" 旁白=0x{nrf:X}" if nrf else ""))
    print(f"\n命令({len(info['commands'])}):")
    for i,(t,n) in enumerate(info['commands']): print(f"  [{i:3d}] p={t} {n}")

def main():
    p = argparse.ArgumentParser(description='HCB脚本文本提取工具')
    s = p.add_subparsers(dest='cmd')
    pe = s.add_parser('extract', aliases=['e']); pe.add_argument('input'); pe.add_argument('-o','--output'); pe.add_argument('-f','--format', choices=['json','txt'], default='json')
    pf = s.add_parser('info'); pf.add_argument('input')
    a = p.parse_args()
    if a.cmd in ('extract','e'): extract(a)
    elif a.cmd == 'info': show_info(a)
    else: p.print_help()

if __name__ == '__main__': main()
