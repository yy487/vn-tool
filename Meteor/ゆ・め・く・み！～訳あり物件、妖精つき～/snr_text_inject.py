# -*- coding: utf-8 -*-
"""
UMakeMe! SNR 脚本 文本注入
用法:
    python snr_text_inject.py <orig_unpacked_dir> <json_dir> <out_dir>

读 <orig_unpacked_dir>/*.txt (原始脚本), 读 <json_dir>/*.json (翻译后),
写 <out_dir>/*.txt (注入后脚本, 保持同样的 CP932 / \\r\\n / 结构).

提取使用的规则必须与 snr_text_extract.py 完全一致, 否则条目会错位.
"""
import sys, os, re, json

# 与 extract 完全同步的正则/规则
from snr_text_extract import _RE_DIALOG, _cmd_translatable_ranges


def inject_script(text, items, script_name='<?>'):
    """
    text  : 原始脚本 (CP932 解码后字符串)
    items : 翻译后的 [{name, message}, ...]
    返回注入后的字符串.
    """
    out_lines = []
    lines = text.split('\r\n')
    idx = 0          # items 游标
    n_items = len(items)

    for ln_no, line in enumerate(lines):
        if line == '' or line.startswith('#') or re.match(r'^\[[^\]]+\]\s*$', line):
            out_lines.append(line)
            continue

        if line.startswith('\t'):
            ranges = _cmd_translatable_ranges(line)
            if not ranges:
                out_lines.append(line)
                continue
            want = len(ranges)
            if idx + want > n_items:
                raise RuntimeError(
                    f"{script_name} line {ln_no}: items 耗尽 (cmd 要 {want} 条)"
                )
            sub_items = items[idx: idx + want]
            idx += want
            # 从右到左替换, 不影响左侧 offset
            new_line = line
            for (s, e, _orig), it in zip(reversed(ranges), reversed(sub_items)):
                new_line = new_line[:s] + it['message'] + new_line[e:]
            out_lines.append(new_line)
            continue

        # 对话
        m = _RE_DIALOG.match(line)
        if m:
            # 空对话未提取, 跳
            if not m.group('text'):
                out_lines.append(line)
                continue
            if idx >= n_items:
                raise RuntimeError(f"{script_name} line {ln_no}: items 耗尽 (dialog)")
            it = items[idx]; idx += 1
            prefix  = m.group('prefix')
            lq      = m.group('lq')
            rq      = m.group('rq')
            voice   = m.group('voice')
            suffix  = m.group('suffix')
            # 重建: prefix + new_name + voice括号 + ： + lq + new_message + rq + suffix
            voice_part = f"({voice})" if voice else ''
            new_name = it['name']
            new_msg  = it['message']
            new_line = f"{prefix}{new_name}{voice_part}：{lq}{new_msg}{rq}{suffix}"
            out_lines.append(new_line)
            continue

        # 旁白 (含日文字符)
        if re.search(r'[\u3040-\u30ff\u3400-\u9fff]', line):
            if idx >= n_items:
                raise RuntimeError(f"{script_name} line {ln_no}: items 耗尽 (narration)")
            it = items[idx]; idx += 1
            out_lines.append(it['message'])
            continue

        # 其他 (无日文的非命令行, 如 SetMode 丢 tab 的)
        out_lines.append(line)

    if idx != n_items:
        print(f"[!] {script_name}: items 剩 {n_items - idx} 条未消耗")

    return '\r\n'.join(out_lines)


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    in_dir, json_dir, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(out_dir, exist_ok=True)

    files = sorted(f for f in os.listdir(in_dir) if f.endswith('.txt'))
    ok, changed, skipped = 0, 0, 0
    for fn in files:
        src = open(os.path.join(in_dir, fn), 'rb').read()
        try:
            text = src.decode('cp932')
        except UnicodeDecodeError as e:
            print(f"[!] {fn}: decode error, skip")
            continue
        jpath = os.path.join(json_dir, fn.replace('.txt', '.json'))
        if not os.path.exists(jpath):
            # 无 JSON: 原样复制
            with open(os.path.join(out_dir, fn), 'wb') as f:
                f.write(src)
            skipped += 1
            continue
        items = json.load(open(jpath, encoding='utf-8'))
        new_text = inject_script(text, items, script_name=fn)
        new_raw = new_text.encode('cp932', errors='replace')
        out_path = os.path.join(out_dir, fn)
        with open(out_path, 'wb') as f:
            f.write(new_raw)
        ok += 1
        if new_raw != src:
            changed += 1

    print(f"[+] injected {ok} files ({changed} changed), skipped {skipped}")


if __name__ == '__main__':
    main()
