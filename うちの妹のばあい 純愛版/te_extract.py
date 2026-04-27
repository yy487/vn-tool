# -*- coding: utf-8 -*-
"""
te_extract.py — 从 Lapis .te 文件提取剧情文本为 JSON

只处理剧情文件（@XXX label 数 >= MIN_LABELS_FOR_STORY），跳过系统/UI 文件。

JSON 格式（每条）:
  {
    "id": int,           # 全局递增
    "message": str,      # 待翻译文本（翻译者只改这一项）
    "_label": str,
    "_seq": int,
    "_tag": str,
    "_file": str,
    "_file_off": str,    # 绝对字节偏移 (hex string)
    "_old_len": int,
    "_linked_to": int,   # (可选) choice_*_inner 指向对应 shown 的 id
    "_marks": list,      # (可选) 选项 inner 的好感度标记
  }
"""
import argparse
import json
import sys
from pathlib import Path

from te_codec import (
    parse_te, find_labels, sjis_runs,
    detect_choice_block, parse_affection_marks,
)


MIN_LABELS_FOR_STORY = 100


def _is_ascii_only(b: bytes) -> bool:
    return all(0x20 <= x <= 0x7E for x in b)


def _is_decoration_header(s: str) -> bool:
    """识别带 ■■■ 装饰的章节/日期标题（不翻译）。

    例: //$00FF80|=■■■　うちの妹のばあい　　６月１０日　■■■|$FFFFFF
    特征：以 //$ 开头，且包含 ■ (SJIS 0x81 A1) 装饰符号 3 个以上
    """
    if not s.startswith('//$'):
        return False
    return s.count('\u25a0') >= 3  # ■ 黑色方块


def classify_run_tag(seq, run_bytes, label_body_first_byte,
                     choice_role):
    """给 SJIS run 打标签。"""
    if choice_role:
        return choice_role

    # 尝试解码
    try:
        msg = run_bytes.decode('cp932')
    except UnicodeDecodeError:
        return 'meta'

    # 纯 ASCII 跳转标签/注释
    if _is_ascii_only(run_bytes):
        if len(msg) <= 30 and ('@' in msg or msg.startswith('_')):
            return 'meta'
        if msg.startswith('//') or msg.startswith('$'):
            return 'meta'

    # ■■■ 装饰的章节日期标题
    if _is_decoration_header(msg):
        return 'meta'

    if len(run_bytes) < 4:
        return 'meta'

    if seq == 0:
        if label_body_first_byte == 0x81:
            return 'dialog'
        return 'narration'

    # seq > 0：说话人名或其他元数据，统归 meta
    return 'meta'


def extract_te_file(file_path: Path, next_id: int) -> tuple:
    """从单个 .te 文件提取翻译条目。返回 (entries, next_id)。"""
    data = file_path.read_bytes()
    p = parse_te(data)
    text = p['text']
    text_start_in_file = p['text_start_in_file']
    labels = find_labels(text)

    entries = []
    cur_id = next_id

    for li, lpos in enumerate(labels):
        label_name = text[lpos:lpos + 4].decode('ascii')
        body_start = lpos + 4
        if li + 1 < len(labels):
            body_end = labels[li + 1] - 1
            while body_end > body_start and text[body_end - 1] == 0x00:
                body_end -= 1
        else:
            body_end = len(text)
            while body_end > body_start and text[body_end - 1] == 0x00:
                body_end -= 1
        body = text[body_start:body_end]
        runs = sjis_runs(body)

        choice_info = detect_choice_block(runs)
        label_body_first_byte = text[body_start] if body_start < len(text) else 0

        label_entries = []
        for seq, (ro, rb) in enumerate(runs):
            choice_role = None
            if choice_info:
                if seq == choice_info['inner_title_idx']:
                    choice_role = 'choice_title_inner'
                elif seq == choice_info['inner_opts_idx']:
                    choice_role = 'choice_options_inner'
                elif seq == choice_info['shown_title_idx']:
                    choice_role = 'choice_title_shown'
                elif seq == choice_info['shown_opts_idx']:
                    choice_role = 'choice_options_shown'
                elif seq == choice_info['deco_title_idx']:
                    choice_role = 'meta'

            tag = classify_run_tag(
                seq, rb, label_body_first_byte, choice_role)

            try:
                msg = rb.decode('cp932')
            except UnicodeDecodeError:
                msg = rb.decode('cp932', errors='replace')
                tag = 'meta'

            file_off = text_start_in_file + body_start + ro

            entry = {
                'id': cur_id,
                'message': msg,
                '_label': label_name,
                '_seq': seq,
                '_tag': tag,
                '_file_off': f'0x{file_off:X}',
                '_old_len': len(rb),
            }

            if tag == 'choice_options_inner':
                entry['_marks'] = parse_affection_marks(msg)

            label_entries.append(entry)
            cur_id += 1

        # 建立 linked_to
        if choice_info:
            shown_title_id = shown_opts_id = None
            for e in label_entries:
                if e['_tag'] == 'choice_title_shown':
                    shown_title_id = e['id']
                elif e['_tag'] == 'choice_options_shown':
                    shown_opts_id = e['id']
            for e in label_entries:
                if e['_tag'] == 'choice_title_inner':
                    e['_linked_to'] = shown_title_id
                elif e['_tag'] == 'choice_options_inner':
                    e['_linked_to'] = shown_opts_id

        entries.extend(label_entries)

    return entries, cur_id


def cmd_extract(input_dir: str, output_dir: str, merge: bool) -> int:
    in_dir = Path(input_dir)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    te_files = sorted(in_dir.rglob('*.te'))
    story_files = []
    for fp in te_files:
        data = fp.read_bytes()
        if not data:
            continue
        try:
            parsed = parse_te(data)
        except Exception as e:
            print(f'  [skip] {fp.name}: {e}', file=sys.stderr)
            continue
        labels = find_labels(parsed['text'])
        if len(labels) >= MIN_LABELS_FOR_STORY:
            story_files.append(fp)
        else:
            print(f'  [skip system] {fp.name} (labels={len(labels)})')

    print(f'\n共 {len(story_files)} 个剧情文件待提取')
    print('=' * 70)

    all_entries = []
    next_id = 0

    for fp in story_files:
        entries, next_id = extract_te_file(fp, next_id)
        for e in entries:
            e['_file'] = fp.name

        tag_counts = {}
        for e in entries:
            tag_counts[e['_tag']] = tag_counts.get(e['_tag'], 0) + 1

        translatable = sum(1 for e in entries if e['_tag'] != 'meta')
        print(f'  {fp.name:18s}  total={len(entries):5d}  '
              f'translatable={translatable:5d}  '
              f'dialog={tag_counts.get("dialog",0):4d}  '
              f'narr={tag_counts.get("narration",0):4d}  '
              f'choice={sum(v for k,v in tag_counts.items() if k.startswith("choice_")):4d}')

        if not merge:
            out_path = out_dir / (fp.stem + '.json')
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(entries, f, ensure_ascii=False, indent=2)

        all_entries.extend(entries)

    if merge:
        with open(out_dir / 'all.json', 'w', encoding='utf-8') as f:
            json.dump(all_entries, f, ensure_ascii=False, indent=2)
        print(f'\n合并到 {out_dir / "all.json"} ({len(all_entries)} 条)')

    print('\n' + '=' * 70)
    total_tags = {}
    for e in all_entries:
        total_tags[e['_tag']] = total_tags.get(e['_tag'], 0) + 1
    print(f'总计: {len(all_entries)} 条')
    for tag, cnt in sorted(total_tags.items(), key=lambda x: -x[1]):
        print(f'  {tag:25s} {cnt:6d}')
    translatable = sum(1 for e in all_entries if e['_tag'] != 'meta')
    print(f'\n需翻译 (非 meta): {translatable}')
    return 0


def main():
    ap = argparse.ArgumentParser(
        description='提取 Lapis .te 剧情文本为翻译 JSON')
    ap.add_argument('input_dir')
    ap.add_argument('output_dir')
    ap.add_argument('--merge', action='store_true')
    args = ap.parse_args()
    return cmd_extract(args.input_dir, args.output_dir, args.merge)


if __name__ == '__main__':
    sys.exit(main() or 0)
