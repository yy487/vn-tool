# -*- coding: utf-8 -*-

import os, sys, json, re, argparse

FULLWIDTH_MARK = re.compile(r'^[\uFF10-\uFF19]+[\uFF21-\uFF3A\uFF41-\uFF5A]+')  # ０-９+ + Ａ-Ｚａ-ｚ+

def split_speaker(raw: str):
    """
    .call 台詞 政紀      -> display='政紀',  id='政紀'
    .call 台詞 ？＠従姉妹 -> display='？',   id='従姉妹'
    .call 台詞 杏子＠妹   -> display='杏子', id='妹'
    .call 台詞 ""         -> display='',    id=''
    """
    s = raw.strip()
    if s == '""' or s == '':
        return '', ''
    if '＠' in s:
        disp, _, cid = s.partition('＠')
        return disp, cid
    return s, s


def extract_file(path: str):
    with open(path, 'rb') as f:
        raw = f.read()
    text = raw.decode('cp932')
    # 保留原始行分隔: 按 \r\n 切, 最后一个空串表示末尾 \r\n
    lines = text.split('\r\n')

    # ---- Pass 1: 扫 .call 台詞 及其正文 ----
    entries = []
    consumed_lines = set()  # 被台詞 pass 处理过的 body 行号
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        m = re.match(r'^\.call\s+台詞\s*(.*)$', s)
        if not m:
            i += 1
            continue

        speaker_line_no = i
        disp, cid = split_speaker(m.group(1))

        # 向后找正文: 允许空行/注释, 遇到 .call/.include/.goto/$ 停
        j = i + 1
        body_line_no = -1
        body = None
        while j < len(lines):
            t = lines[j]
            ts = t.strip()
            if ts == '' or ts.startswith('//'):
                j += 1
                continue
            if ts.startswith('.') or ts.startswith('$'):
                break  # 没找到正文
            body = t
            body_line_no = j
            break

        if body is None:
            i += 1
            continue

        # 剥离立绘前缀 (如 "５Ｂ" "１０Ａ"), 注入时原样拼回
        prefix = ''
        body_stripped = body
        mm = FULLWIDTH_MARK.match(body)
        if mm:
            prefix = mm.group(0)
            body_stripped = body[len(prefix):]

        # name: 空字符串 / "" 当作旁白(None); ？ 也当成一个名字保留
        name = disp if disp else None

        entries.append({
            'json': None,  # 后面统一分配 id
            'line_no': body_line_no,
            'speaker_line': speaker_line_no,
            'orig_name_raw': m.group(1),
            'orig_message': body,
            'prefix': prefix,
            'name': name,
            'message': body_stripped,
            'kind': 'dialog',
        })
        consumed_lines.add(body_line_no)
        i = j + 1

    # ---- Pass 2: 扫裸旁白 (不在 台詞 管辖下的纯文本行) ----
    for idx, ln in enumerate(lines):
        if idx in consumed_lines:
            continue
        s = ln.strip()
        if not s:
            continue
        if s.startswith('.') or s.startswith('$') or s.startswith('//'):
            continue
        # 跳过立绘标记开头的 (理论上裸旁白不应出现, 但保险起见)
        if FULLWIDTH_MARK.match(ln.lstrip()):
            continue
        entries.append({
            'json': None,
            'line_no': idx,
            'speaker_line': -1,
            'orig_name_raw': '',
            'orig_message': ln,
            'prefix': '',
            'name': None,
            'message': ln,
            'kind': 'narration',
        })

    # 按 line_no 排序, 重新分配 id (保持剧情顺序)
    entries.sort(key=lambda e: e['line_no'])
    for new_id, e in enumerate(entries):
        item = {'id': new_id}
        if e['name'] is not None:
            item['name'] = e['name']
        item['message'] = e['message']
        e['json'] = item

    return entries, lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='.dac/.dacz 文件 或 目录')
    ap.add_argument('-o', '--output', required=True, help='输出 JSON 路径 (单文件) 或 目录 (批量)')
    ap.add_argument('--meta', help='元信息输出路径 (默认与 output 同目录)')
    args = ap.parse_args()

    if os.path.isfile(args.input):
        entries, _ = extract_file(args.input)
        json_items = [e['json'] for e in entries]
        meta_items = [{
            'id': e['json']['id'],
            'line_no': e['line_no'],
            'speaker_line': e['speaker_line'],
            'orig_name_raw': e['orig_name_raw'],
            'orig_message': e['orig_message'],
            'prefix': e['prefix'],
            'kind': e['kind'],
        } for e in entries]

        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(json_items, f, ensure_ascii=False, indent=2)
        meta_path = args.meta or (args.output + '.meta.json')
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump({'file': os.path.basename(args.input), 'entries': meta_items},
                      f, ensure_ascii=False, indent=2)
        print(f'[OK] {args.input}: {len(entries)} 条  ->  {args.output}')
    else:
        os.makedirs(args.output, exist_ok=True)
        total = 0
        for name in sorted(os.listdir(args.input)):
            if not (name.endswith('.dac') or name.endswith('.dacz')):
                continue
            src = os.path.join(args.input, name)
            entries, _ = extract_file(src)
            json_items = [e['json'] for e in entries]
            out_json = os.path.join(args.output, name + '.json')
            with open(out_json, 'w', encoding='utf-8') as f:
                json.dump(json_items, f, ensure_ascii=False, indent=2)
            meta_items = [{
                'id': e['json']['id'],
                'line_no': e['line_no'],
                'speaker_line': e['speaker_line'],
                'orig_name_raw': e['orig_name_raw'],
                'orig_message': e['orig_message'],
                'prefix': e['prefix'],
                'kind': e['kind'],
            } for e in entries]
            with open(out_json + '.meta.json', 'w', encoding='utf-8') as f:
                json.dump({'file': name, 'entries': meta_items},
                          f, ensure_ascii=False, indent=2)
            print(f'  {name}: {len(entries)} 条')
            total += len(entries)
        print(f'[OK] 共 {total} 条')


if __name__ == '__main__':
    main()
