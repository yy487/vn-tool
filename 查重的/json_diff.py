#!/usr/bin/env python3
"""
json_diff.py - 对比两个版本的CSB提取JSON文本差异
==================================================
Usage:
  python json_diff.py <dir_v1> <dir_v2> [output.txt]

Example:
  python json_diff.py 1.00/ 1.03/ diff_report.txt
"""

import json, sys, os, glob


def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def diff_one_file(path1, path2):
    """对比两个JSON文件，返回差异列表"""
    d1 = load_json(path1)
    d2 = load_json(path2)

    diffs = []

    # 按id建索引
    map1 = {e['id']: e for e in d1}
    map2 = {e['id']: e for e in d2}

    all_ids = sorted(set(list(map1.keys()) + list(map2.keys())))

    for eid in all_ids:
        e1 = map1.get(eid)
        e2 = map2.get(eid)

        if e1 and not e2:
            diffs.append(('REMOVED', eid, e1, None))
        elif e2 and not e1:
            diffs.append(('ADDED', eid, None, e2))
        else:
            if e1['message'] != e2['message']:
                diffs.append(('MSG_CHANGED', eid, e1, e2))
            if e1.get('name', '') != e2.get('name', ''):
                diffs.append(('NAME_CHANGED', eid, e1, e2))

    return diffs, len(d1), len(d2)


def main():
    if len(sys.argv) < 3:
        print("Usage: json_diff.py <dir_v1> <dir_v2> [output.txt]")
        sys.exit(1)

    dir1 = sys.argv[1]
    dir2 = sys.argv[2]
    out_path = sys.argv[3] if len(sys.argv) > 3 else None

    files1 = {os.path.basename(f) for f in glob.glob(os.path.join(dir1, '*.json'))}
    files2 = {os.path.basename(f) for f in glob.glob(os.path.join(dir2, '*.json'))}

    all_files = sorted(files1 | files2)
    only1 = sorted(files1 - files2)
    only2 = sorted(files2 - files1)
    common = sorted(files1 & files2)

    lines = []
    def out(s=''):
        lines.append(s)
        print(s)

    out(f'═══════════════════════════════════════════')
    out(f'  JSON Diff: {os.path.basename(dir1.rstrip("/"))} vs {os.path.basename(dir2.rstrip("/"))}')
    out(f'═══════════════════════════════════════════')
    out(f'  v1: {len(files1)} files  ({dir1})')
    out(f'  v2: {len(files2)} files  ({dir2})')
    out(f'  Common: {len(common)}  Only v1: {len(only1)}  Only v2: {len(only2)}')
    out()

    if only1:
        out(f'── Only in v1 ({len(only1)}) ──')
        for f in only1:
            out(f'  - {f}')
        out()

    if only2:
        out(f'── Only in v2 ({len(only2)}) ──')
        for f in only2:
            out(f'  + {f}')
        out()

    total_diffs = 0
    changed_files = []

    for fname in common:
        p1 = os.path.join(dir1, fname)
        p2 = os.path.join(dir2, fname)
        diffs, cnt1, cnt2 = diff_one_file(p1, p2)

        if not diffs and cnt1 == cnt2:
            continue

        changed_files.append(fname)
        total_diffs += len(diffs)

        out(f'── {fname} (v1:{cnt1} entries → v2:{cnt2} entries, {len(diffs)} diffs) ──')

        for dtype, eid, e1, e2 in diffs:
            if dtype == 'MSG_CHANGED':
                name = e1.get('name', '') or '(旁白)'
                out(f'  [{eid}] {name}')
                out(f'    v1: {e1["message"]}')
                out(f'    v2: {e2["message"]}')
                out()
            elif dtype == 'NAME_CHANGED':
                out(f'  [{eid}] NAME: "{e1.get("name","")}" → "{e2.get("name","")}"')
                out()
            elif dtype == 'REMOVED':
                out(f'  [{eid}] REMOVED: {e1["message"][:60]}')
                out()
            elif dtype == 'ADDED':
                out(f'  [{eid}] ADDED: {e2["message"][:60]}')
                out()

    out(f'═══════════════════════════════════════════')
    out(f'  Summary: {len(changed_files)} files changed, {total_diffs} diffs total')
    if not changed_files:
        out(f'  No text differences found!')
    else:
        out(f'  Changed: {", ".join(changed_files)}')
    out(f'═══════════════════════════════════════════')

    if out_path:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print(f'\nReport saved to {out_path}')


if __name__ == '__main__':
    main()
