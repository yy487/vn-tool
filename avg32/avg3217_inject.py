#!/usr/bin/env python3
"""
avg3217_inject.py — AVG3217 SEEN.TXT 文本注入

用法:
    # 默认变长注入 (GBK 编码)
    python avg3217_inject.py SEEN.TXT seen_zh.json -o SEEN_NEW.TXT

    # 等长模式 (兜底)
    python avg3217_inject.py SEEN.TXT seen_zh.json -o SEEN_NEW.TXT --equal-length

    # 不确定自动识别时, 加 --positions-file 手动指定需要修正的 u32 位置
    python avg3217_inject.py SEEN.TXT seen_zh.json -o SEEN_NEW.TXT --positions-file positions.json

    # 严格模式: 任意 orig_hex 不匹配立即失败
    python avg3217_inject.py SEEN.TXT seen_zh.json -o SEEN_NEW.TXT --strict

失败条目 (编码失败 / orig 不匹配 / overflow) 导出 --fix-out 供人工处理.

positions.json (手工指定 u32 位置) 格式:
    {
      "SEEN100.TXT": [
        {"u32_off": 4096, "target": 5000, "kind": "goto_manual"}
      ]
    }
"""
import struct, json, sys, argparse
from avg3217_common import (
    pacl_unpack, pacl_repack,
    pack_decompress, pack_compress,
    parse_tpc32, find_all_jump_ops, find_all_text_ops,
    apply_fixups,
)


def build_tasks_from_entries(entries, plains):
    """把 entries 转换成 per-file 写入任务.
       返回 tasks_by_file = {fname: [{off, orig_len, orig_hex, text, src_entry, label}, ...]}
    """
    tasks_by_file = {}
    for e in entries:
        f = e.get('_file')
        if not f or f not in plains:
            continue
        is_paired = '_body_text_off' in e
        if is_paired:
            # name + body 两条分别写
            tasks_by_file.setdefault(f, []).append({
                'off': e['_text_off'],
                'orig_len': e['_orig_len'],
                'orig_hex': e['_orig_hex'],
                'text': f'【{e["name"]}】',
                'src_entry': e,
                'label': 'name',
            })
            tasks_by_file.setdefault(f, []).append({
                'off': e['_body_text_off'],
                'orig_len': e['_body_orig_len'],
                'orig_hex': e['_body_orig_hex'],
                'text': e['message'],  # body 直接就是对话, 不加 【】　 前缀
                'src_entry': e,
                'label': 'body',
            })
        else:
            name = e.get('name', '')
            if name:
                full = f'【{name}】{e["message"]}'
            else:
                full = e['message']
            tasks_by_file.setdefault(f, []).append({
                'off': e['_text_off'],
                'orig_len': e['_orig_len'],
                'orig_hex': e['_orig_hex'],
                'text': full,
                'src_entry': e,
                'label': 'solo',
            })
    return tasks_by_file


def encode_text(text, enc):
    """编码. 返回 (bytes, err_kind, detail). 失败时 bytes=None."""
    if '\ufffd' in text:
        return None, 'has_fffd', '含 \\ufffd'
    # 半角 ASCII 在日语字体系统里会走 FONTHAN 可能显示错, 转全角
    # (这是 AVG3217 里 FONTCHANGER 相关的经验观察, 按需启用)
    try:
        return text.encode(enc), None, None
    except UnicodeEncodeError as ex:
        return None, 'encode_error', str(ex)


def make_fix_record(task, reason, detail):
    """构造 fix-out 记录"""
    e = task['src_entry']
    rec = {
        'reason': reason,
        'detail': detail,
        'failed_field': task['label'],
        'id': e.get('id'),
        '_file': e.get('_file'),
        '_op': e.get('_op'),
        '_line': e.get('_line'),
    }
    if 'name' in e:
        rec['name'] = e['name']
    rec['orig_hex'] = e.get('_orig_hex')
    if e.get('_body_orig_hex'):
        rec['body_orig_hex'] = e['_body_orig_hex']
    try:
        rec['orig_text'] = bytes.fromhex(e.get('_orig_hex', '')).decode('cp932', errors='replace')
    except Exception:
        rec['orig_text'] = ''
    if e.get('_body_orig_hex'):
        try:
            rec['body_orig_text'] = bytes.fromhex(e['_body_orig_hex']).decode('cp932', errors='replace')
        except Exception:
            pass
    rec['message'] = e.get('message', '')
    return rec


def process_file(fname, plain, tasks, args, positions_for_file):
    """处理一个 TPC32 文件, 返回 (new_plain, stats, fix_records)"""
    stats = {'total': 0, 'skipped': 0, 'mismatches': 0, 'padded': 0, 'overflow': 0}
    fix_records = []
    
    try:
        info = parse_tpc32(plain)
    except (AssertionError, struct.error) as ex:
        print(f'[!] {fname} 非 TPC32 ({ex}), 原样保留', file=sys.stderr)
        return plain, stats, fix_records
    
    # 跳转 u32 字段:
    # - 等长模式: 不需要 (不改跳转)
    # - 变长模式: 扫所有子脚本的跳转 (每个子脚本独立, u32 相对子脚本起点)
    jumps = []
    if not args.equal_length:
        jumps = find_all_jump_ops(plain, info)
        # 手工位置作为补充
        if positions_for_file:
            existing_u32 = {j['u32_off'] for j in jumps}
            # 手工 positions 需包含 sub_name 字段 (定位到哪个子脚本)
            for p in positions_for_file:
                if p['u32_off'] not in existing_u32:
                    jumps.append({
                        'kind': p.get('kind', 'manual'),
                        'op_off': p.get('op_off', 0),
                        'u32_off': p['u32_off'],
                        'target': p['target'],
                        'target_rel': p.get('target_rel', 0),
                        'sub_name': p.get('sub_name', 'e0'),
                    })
    
    # 收集 edits
    edits = []
    for t in tasks:
        off = t['off']
        orig_len = t['orig_len']
        orig_hex = t['orig_hex']
        
        # 验证原字节
        actual_hex = bytes(plain[off:off+orig_len]).hex()
        if orig_hex and actual_hex != orig_hex:
            stats['mismatches'] += 1
            if args.strict:
                raise RuntimeError(f'{fname} @0x{off:X} ({t["label"]}) 原字节不符: '
                                   f'expect {orig_hex[:60]} actual {actual_hex[:60]}')
            print(f'[!] {fname} @0x{off:X} ({t["label"]}) 原字节不符', file=sys.stderr)
            fix_records.append(make_fix_record(t, 'mismatch',
                f'expect {orig_hex[:60]} actual {actual_hex[:60]}'))
            stats['skipped'] += 1
            continue
        
        # 编码
        new_bytes, err, detail = encode_text(t['text'], args.encoding)
        if new_bytes is None:
            if err == 'has_fffd':
                new_bytes = bytes.fromhex(orig_hex)
            else:
                print(f'[!] {fname} id={t["src_entry"]["id"]} ({t["label"]}) 编码失败: {detail}',
                      file=sys.stderr)
                fix_records.append(make_fix_record(t, err, detail))
                stats['skipped'] += 1
                continue
        
        # 等长模式
        if args.equal_length and len(new_bytes) != orig_len:
            if len(new_bytes) < orig_len:
                pad_needed = orig_len - len(new_bytes)
                pad_char = '\u3000'.encode(args.encoding)
                if pad_needed % len(pad_char) != 0:
                    fix_records.append(make_fix_record(t, 'odd_length_diff',
                        f'差 {pad_needed}B 无法用全角空格填充'))
                    stats['skipped'] += 1
                    continue
                new_bytes += pad_char * (pad_needed // len(pad_char))
                stats['padded'] += 1
            else:
                overflow = len(new_bytes) - orig_len
                fix_records.append(make_fix_record(t, 'overflow', f'+{overflow}B'))
                stats['overflow'] += 1
                stats['skipped'] += 1
                continue
        
        edits.append({
            'off': off,
            'orig_len': orig_len,
            'new_bytes': new_bytes,
        })
        stats['total'] += 1
    
    # 应用修正
    if not edits:
        new_plain = plain
    elif args.equal_length:
        p = bytearray(plain)
        for e in edits:
            p[e['off']:e['off']+e['orig_len']] = e['new_bytes']
        new_plain = bytes(p)
    else:
        # 变长: 用 common 的 apply_fixups (info 而非 tail_start/code_entries)
        new_plain = apply_fixups(plain, info, jumps, edits)
    
    return new_plain, stats, fix_records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='原 SEEN.TXT')
    ap.add_argument('json', help='翻译后的 JSON')
    ap.add_argument('-o', '--output', default='SEEN.NEW.TXT', help='输出 SEEN.TXT')
    ap.add_argument('--encoding', default='gbk', help='文本编码 (默认 gbk)')
    ap.add_argument('--strict', action='store_true', help='任意 orig 不匹配立即失败')
    ap.add_argument('--equal-length', action='store_true', default=True,
                    help='等长模式 (默认, 零风险, 不修跳转)')
    ap.add_argument('--varlen', action='store_true',
                    help='变长模式 (谨慎: 仅当 --positions-file 精确指定 u32 位置时才安全)')
    ap.add_argument('--fix-out', default=None, help='失败条目导出 JSON')
    ap.add_argument('--positions-file', default=None,
                    help='手工指定 u32 修正位置 (JSON 格式, 仅变长模式下生效)')
    args = ap.parse_args()
    
    # --varlen 覆盖 --equal-length
    if args.varlen:
        args.equal_length = False
    
    # 变长模式下检查 (提示, 不强制 positions-file)
    if args.varlen and not args.positions_file:
        print('[*] --varlen 模式: 将自动扫描跳转 (goto/gosub/cond/select)', file=sys.stderr)
        print('    依据: u32 target 相对 tail_start, 落在 tail 范围内即认为合法', file=sys.stderr)
        print('    如果自动扫描遗漏或错识, 可用 --positions-file 补充/覆盖', file=sys.stderr)
    
    raw = open(args.input, 'rb').read()
    items = pacl_unpack(raw)
    entries = json.load(open(args.json, encoding='utf-8'))
    
    # 先解压所有
    plains = {}
    metas = {}
    for fname, csize, ucsize, flag, blk in items:
        plain = pack_decompress(blk)
        plains[fname] = plain
        metas[fname] = (ucsize, flag)
    print(f'[*] 解压 {len(plains)} 个文件', file=sys.stderr)
    
    # 构建任务
    tasks_by_file = build_tasks_from_entries(entries, plains)
    
    # 加载手工 positions
    manual_positions = {}
    if args.positions_file:
        manual_positions = json.load(open(args.positions_file, encoding='utf-8'))
        total_manual = sum(len(v) for v in manual_positions.values())
        print(f'[*] 手工 u32 位置: {total_manual} 条, 覆盖 {len(manual_positions)} 文件',
              file=sys.stderr)
    
    # 处理每个文件
    agg = {'total': 0, 'skipped': 0, 'mismatches': 0, 'padded': 0, 'overflow': 0}
    all_fix = []
    new_items = []
    
    for fname, csize, ucsize, flag, blk in items:
        plain = plains[fname]
        tasks = tasks_by_file.get(fname, [])
        positions = manual_positions.get(fname, [])
        
        new_plain, stats, fix_records = process_file(fname, plain, tasks, args, positions)
        
        for k in agg: agg[k] += stats[k]
        all_fix.extend(fix_records)
        
        new_blk = pack_compress(new_plain)
        new_items.append((fname, new_blk, len(new_plain), flag))
    
    print(f'[*] 写入: {agg["total"]} / 跳过: {agg["skipped"]} / 不匹配: {agg["mismatches"]}',
          file=sys.stderr)
    if args.equal_length:
        print(f'[*] 等长填充: {agg["padded"]} / 超长: {agg["overflow"]}', file=sys.stderr)
    
    if args.fix_out and all_fix:
        with open(args.fix_out, 'w', encoding='utf-8') as f:
            json.dump(all_fix, f, ensure_ascii=False, indent=2)
        print(f'[*] 失败条目导出: {args.fix_out} ({len(all_fix)} 条)', file=sys.stderr)
    
    out_data = pacl_repack(new_items)
    with open(args.output, 'wb') as f:
        f.write(out_data)
    print(f'[*] 写入 {args.output} ({len(out_data)} B)', file=sys.stderr)


if __name__ == '__main__':
    main()
