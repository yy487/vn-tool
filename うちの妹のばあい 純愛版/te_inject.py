# -*- coding: utf-8 -*-
"""
te_inject.py — 把翻译好的 JSON 写回 Lapis .te 文件（变长注入）

核心流程：
  1. 收集所有替换点 (file_off, old_len, new_bytes)
  2. 拼接新 text section
  3. 建立 offset_map: 老 text 偏移 → 新 text 偏移
  4. 用 map 修正 code 段和 tail 段中所有引用
  5. build_te 重组文件
"""
import argparse
import json
import sys
from pathlib import Path

from te_codec import (
    parse_te, build_te,
    collect_ref_targets, remap_code_refs,
    collect_tail_ref_targets, remap_tail_refs,
    apply_affection_marks,
)


def resolve_inject_message(entry, entries_by_id):
    """决定一条 entry 要注入什么。返回 str 或 None（跳过 = meta）。"""
    tag = entry['_tag']
    if tag == 'meta':
        return None

    zh = entry.get('zh', '').strip()

    if tag in ('dialog', 'narration',
               'choice_title_shown', 'choice_options_shown'):
        return zh if zh else entry['message']

    if tag == 'choice_title_inner':
        linked = entries_by_id.get(entry.get('_linked_to'))
        if linked and linked.get('zh', '').strip():
            return linked['zh']
        return entry['message']

    if tag == 'choice_options_inner':
        linked = entries_by_id.get(entry.get('_linked_to'))
        marks = entry.get('_marks', [])
        if linked and linked.get('zh', '').strip():
            try:
                return apply_affection_marks(linked['zh'], marks)
            except ValueError as e:
                print(f"  ! 选项标记回贴失败 (id={entry['id']}): {e}")
                return entry['message']
        return entry['message']

    return entry.get('message')


def inject_one_file(file_path, entries, out_path, verbose=False):
    """重建单个 .te 文件。返回统计 dict。"""
    data = file_path.read_bytes()
    p = parse_te(data)
    text = p['text']
    text_start = p['text_start_in_file']
    old_text_size = len(text)
    code = p['code']
    tail = p['tail']

    entries_by_id = {e['id']: e for e in entries}

    edits = []  # [(text_off, old_len, new_bytes, entry_id)]
    stats = dict(total=0, injected=0, skipped_meta=0, unchanged=0)

    for e in entries:
        stats['total'] += 1
        if e['_tag'] == 'meta':
            stats['skipped_meta'] += 1
            continue

        new_msg = resolve_inject_message(e, entries_by_id)
        if new_msg is None:
            stats['skipped_meta'] += 1
            continue

        # 编码：默认 CP932 (Shift-JIS)
        try:
            new_bytes = new_msg.encode('cp932')
        except UnicodeEncodeError as ee:
            raise ValueError(
                f"entry id={e['id']} 无法用 CP932 编码: "
                f"{ee.reason} (字符 {new_msg[ee.start:ee.end]!r})\n"
                f"  message: {new_msg!r}"
            )

        old_msg = e['message']
        # 未改动：跳过
        if new_msg == old_msg:
            stats['unchanged'] += 1
            continue

        file_off = int(e['_file_off'], 16)
        text_off = file_off - text_start
        old_len = e['_old_len']

        if text_off < 0 or text_off + old_len > old_text_size:
            raise ValueError(
                f"entry id={e['id']} 偏移越界: "
                f"0x{text_off:x}+0x{old_len:x} vs text_size 0x{old_text_size:x}")

        edits.append((text_off, old_len, new_bytes, e['id']))
        stats['injected'] += 1

    # 排序 + 不重叠校验
    edits.sort(key=lambda x: x[0])
    for i in range(1, len(edits)):
        if edits[i][0] < edits[i - 1][0] + edits[i - 1][1]:
            raise ValueError(
                f'edits 重叠: id={edits[i-1][3]} (0x{edits[i-1][0]:x}+{edits[i-1][1]}) '
                f'与 id={edits[i][3]} (0x{edits[i][0]:x})')

    ref_targets = collect_ref_targets(code, old_text_size)
    tail_targets = collect_tail_ref_targets(tail, old_text_size)
    all_targets = ref_targets | tail_targets

    # 构造新 text + offset_map
    new_parts = []
    offset_map = {}
    cursor = 0
    new_cursor = 0

    for off, old_len, new_bytes, _eid in edits:
        seg_len = off - cursor
        new_parts.append(text[cursor:off])
        for t in all_targets:
            if cursor <= t < off:
                offset_map[t] = new_cursor + (t - cursor)
        new_cursor += seg_len

        # 被替换段：引用目标若在此段内部都指向替换段起点
        for t in all_targets:
            if off <= t < off + old_len:
                offset_map[t] = new_cursor
        new_parts.append(new_bytes)
        new_cursor += len(new_bytes)
        cursor = off + old_len

    if cursor < old_text_size:
        for t in all_targets:
            if cursor <= t < old_text_size:
                offset_map[t] = new_cursor + (t - cursor)
        new_parts.append(text[cursor:])
        new_cursor += (old_text_size - cursor)

    new_text = b''.join(new_parts)
    assert len(new_text) == new_cursor

    # u24 上限检查 (text_offset << 4 必须 < 0x1000000)
    if new_cursor > 0:
        max_ref = (new_cursor - 1) << 4
        if max_ref > 0xFFFFFF:
            raise ValueError(
                f'新 text 0x{new_cursor:x} 超过引用编码上限 '
                f'(max ≈ 0x{0xFFFFFF >> 4:x})')

    # 修正 code + tail
    new_code = remap_code_refs(code, old_text_size, offset_map)
    new_tail = remap_tail_refs(tail, old_text_size, offset_map)

    new_data = build_te(p['header'], new_code, new_text, new_tail)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(new_data)

    stats['old_size'] = len(data)
    stats['new_size'] = len(new_data)
    stats['old_text_size'] = old_text_size
    stats['new_text_size'] = len(new_text)
    stats['edits'] = len(edits)

    if verbose:
        print(f"    edits={len(edits)}, "
              f"text: 0x{old_text_size:x} -> 0x{len(new_text):x} "
              f"(delta {len(new_text)-old_text_size:+d})")

    return stats


def cmd_inject(input_dir, json_src, output_dir, verbose=False) -> int:
    in_dir = Path(input_dir)
    json_path = Path(json_src)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    file_entries = {}
    if json_path.is_file():
        with open(json_path, 'r', encoding='utf-8') as f:
            all_entries = json.load(f)
        for e in all_entries:
            file_entries.setdefault(e['_file'], []).append(e)
    elif json_path.is_dir():
        for jp in sorted(json_path.glob('*.json')):
            if jp.name == 'all.json':
                continue
            with open(jp, 'r', encoding='utf-8') as f:
                entries = json.load(f)
            if entries:
                fn = entries[0]['_file']
                file_entries[fn] = entries
    else:
        raise FileNotFoundError(f'{json_path} 不存在')

    print(f'待注入文件: {len(file_entries)}')
    print('=' * 72)

    total_edits = 0
    total_old = 0
    total_new = 0
    fails = []

    for fn, entries in sorted(file_entries.items()):
        src = in_dir / fn
        if not src.exists():
            src = in_dir / 'sce' / fn
            if not src.exists():
                print(f'  [miss] {fn} 源文件找不到')
                fails.append(fn)
                continue
        dst = out_dir / fn
        try:
            stats = inject_one_file(src, entries, dst, verbose=verbose)
            print(f'  {fn:18s}  edits={stats["edits"]:5d}  '
                  f'size={stats["old_size"]:>7d} -> {stats["new_size"]:>7d}  '
                  f'(delta {stats["new_size"]-stats["old_size"]:+d})')
            total_edits += stats['edits']
            total_old += stats['old_size']
            total_new += stats['new_size']
        except Exception as e:
            print(f'  [FAIL] {fn}: {e}')
            fails.append(fn)

    print('=' * 72)
    print(f'成功: {len(file_entries) - len(fails)}, 失败: {len(fails)}')
    print(f'总 edits: {total_edits}')
    print(f'总大小: {total_old:,} -> {total_new:,} '
          f'(delta {total_new - total_old:+,})')
    if fails:
        print('\n失败列表:')
        for f in fails:
            print(f'  - {f}')
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(
        description='将翻译 JSON 注入回 Lapis .te 文件（变长）')
    ap.add_argument('input_dir')
    ap.add_argument('json_src')
    ap.add_argument('output_dir')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()
    return cmd_inject(args.input_dir, args.json_src, args.output_dir,
                      verbose=args.verbose)


if __name__ == '__main__':
    sys.exit(main() or 0)
