"""silky_inject.py — Silky MES translate.txt + op.txt -> 新 op.txt 译文注入。

输入：
  - 原始 *.op.txt（silky_op disasm 产物）
  - translate.txt（译者修改过的 ◆ 行）

输出：
  - 新的 *.op.txt（◆ 行的译文已替换到对应 STR_CRYPT/STR_UNCRYPT 参数行）

之后再用 silky_op asm 把新 op.txt 编回 *.MES。

关键约束：
  * translate.txt 里 ◆ 行用 \\n 分隔的"段数"必须等于原 ◇ 行的段数。
    超出的段被丢弃，缺少的段填空字符串。
  * 注入只改字符串的内容，不改 op 流结构 — 跳转/偏移由 silky_op asm 阶段重新计算。

CLI:
  python silky_inject.py <orig.op.txt> <translate.txt> <new.op.txt>
"""

import json

# 共享的对话块识别集合（与 silky_extract 完全一致）
_NAME_BLOCK_PUSH_VALS = frozenset([83886080, 167772160])

_BLOCK_INTERNAL_OPCODES = frozenset([
    '#1-PUSH', '#1-PUSH_STR', '#1-RETURN',
    '#1-ff', '#1-fe', '#1-fd', '#1-fc', '#1-fb', '#1-fa',
    '#1-JUMP_2', '#1-3a', '#1-3b', '#1-3c', '#1-3d', '#1-3e', '#1-3f',
    '#1-40', '#1-41', '#1-42', '#1-43',
    '#1-34', '#1-35', '#1-37', '#1-38',
    '#1-10', '#1-11', '#1-0c', '#1-0d', '#1-0e', '#1-0f',
    '#1-02', '#1-03', '#1-04', '#1-05', '#1-06',
    '#1-17', '#1-18',
])

_BLOCK_END_OPCODES = frozenset([
    '#1-MESSAGE', '#1-JUMP', '#1-MSG_OFSETTER', '#1-SPEC_OFSETTER',
    '#1-1a', '#1-1b',
])

_STR_OPCODE_LINES = frozenset(['#1-STR_CRYPT', '#1-STR_UNCRYPT'])


def _is_label_or_free(line: str) -> bool:
    return line.startswith('#0-') or line.startswith('#2-') or line.startswith('#3')


def _parse_json_str(arg_line: str) -> str:
    try:
        val = json.loads(arg_line)
        if isinstance(val, list) and len(val) > 0:
            return str(val[0])
    except (json.JSONDecodeError, IndexError):
        pass
    return arg_line


def _parse_json_first_int(arg_line: str) -> int:
    try:
        val = json.loads(arg_line)
        if isinstance(val, list) and len(val) > 0:
            return int(val[0])
    except (json.JSONDecodeError, IndexError, ValueError):
        pass
    return 0


def _try_match_ruby(lines, str_idx, total):
    """识别 ruby 段。详见 silky_extract._try_match_ruby。"""
    if str_idx + 11 >= total:
        return None
    if (lines[str_idx].rstrip('\n') != '#1-STR_CRYPT' or
        lines[str_idx + 2].rstrip('\n') != '#1-TO_NEW_STRING' or
        lines[str_idx + 4].rstrip('\n') != '#1-STR_UNCRYPT' or
        lines[str_idx + 6].rstrip('\n') != '#1-STR_CRYPT' or
        lines[str_idx + 8].rstrip('\n') != '#1-RETURN' or
        lines[str_idx + 10].rstrip('\n') != '#1-STR_CRYPT'):
        return None
    if _parse_json_first_int(lines[str_idx + 3].rstrip('\n')) != 1:
        return None
    sep = _parse_json_str(lines[str_idx + 5].rstrip('\n'))
    if sep != ' ':
        return None
    return {
        'prev_arg_idx': str_idx + 1,
        'sep_arg_idx': str_idx + 5,
        'reading_arg_idx': str_idx + 7,
        'base_arg_idx': str_idx + 11,
        'orig_reading': _parse_json_str(lines[str_idx + 7].rstrip('\n')),
        'end_idx': str_idx + 12,
    }


def _detect_name_block(lines, i, total):
    """识别角色名块，返回名字串或 None。逻辑与 silky_extract 完全一致。"""
    if i + 7 >= total:
        return None
    cl = lines[i].rstrip('\n')
    if cl != '#1-PUSH_STR':
        return None
    arg = _parse_json_str(lines[i + 1].rstrip('\n'))
    try:
        arg.encode('ascii')
        return None
    except UnicodeEncodeError:
        pass
    if lines[i + 2].rstrip('\n') != '#1-PUSH':
        return None
    try:
        push_val = json.loads(lines[i + 3].rstrip('\n'))
        if not (isinstance(push_val, list) and push_val[0] in _NAME_BLOCK_PUSH_VALS):
            return None
    except (json.JSONDecodeError, IndexError, KeyError):
        return None
    if (i + 6 < total and
        lines[i + 4].rstrip('\n') == '#1-PUSH' and
        lines[i + 6].rstrip('\n') == '#1-18'):
        return arg
    if (i + 10 < total and
        lines[i + 4].rstrip('\n') == '#1-PUSH' and
        lines[i + 6].rstrip('\n') == '#1-34' and
        lines[i + 8].rstrip('\n') == '#1-PUSH' and
        lines[i + 10].rstrip('\n') == '#1-18'):
        return arg
    return None


def _collect_text_block(lines, start, total):
    """收集对话块中所有 STR 字符串，注音段合并。与 silky_extract 一致。

    text_parts 元素：
      ('text', arg_line_idx, text_value)
      ('ruby', ruby_dict)
    """
    text_parts = []
    detected_name = None
    name_arg_line_idx = None
    i = start

    while i < total:
        cl = lines[i].rstrip('\n')

        name = _detect_name_block(lines, i, total)
        if name is not None:
            detected_name = name
            name_arg_line_idx = i + 1
            i += 2
            continue

        if cl in _STR_OPCODE_LINES:
            ruby = _try_match_ruby(lines, i, total)
            if ruby is not None:
                text_parts.append(('ruby', ruby))
                i = ruby['end_idx']
                continue

            arg_line = lines[i + 1].rstrip('\n') if i + 1 < total else '[]'
            text_val = _parse_json_str(arg_line)
            text_parts.append(('text', i + 1, text_val))
            i += 2
        elif cl in _BLOCK_END_OPCODES:
            break
        elif cl in _BLOCK_INTERNAL_OPCODES:
            i += 2
        elif _is_label_or_free(cl):
            i += 1
        elif cl.startswith('#1-'):
            i += 2
        elif cl.startswith('$'):
            i += 1
        else:
            i += 1

    return text_parts, i, detected_name, name_arg_line_idx


def import_text(opcode_txt_path: str, text_txt_path: str, output_txt_path: str) -> int:
    """把 translate.txt 的 ◆ 行注入回 op.txt 的 STR 参数行。

    translate.txt 行格式：
      ◆0001◆name◆角色译名         (角色名条目)
      ◆0002◆译文段1\\n译文段2\\n... (文本条目，\\n 分隔多 STR)

    返回成功扫描的条目数。
    """
    # 1. 读 translate.txt，解析所有 ◆ 行
    translations = {}      # seq_idx -> translated string
    name_translations = {} # seq_idx -> translated name
    with open(text_txt_path, 'r', encoding='utf-8-sig') as f:
        for tline in f:
            tline = tline.rstrip('\n')
            if not tline.startswith('\u25c6'):
                continue
            rest = tline[1:]
            parts = rest.split('\u25c6')
            if len(parts) >= 3 and parts[1] == 'name':
                try:
                    name_translations[int(parts[0])] = parts[2]
                except ValueError:
                    pass
            elif len(parts) >= 2:
                try:
                    translations[int(parts[0])] = parts[1]
                except ValueError:
                    pass

    # 2. 读原 op.txt，按 extract 同样的逻辑遍历
    with open(opcode_txt_path, 'r', encoding='utf-8-sig') as f:
        lines = f.readlines()

    seq = 0
    i = 0
    total = len(lines)

    while i < total:
        line = lines[i].rstrip('\n')

        is_message_block = (line == '#1-MESSAGE')
        is_standalone_str = (line in _STR_OPCODE_LINES)

        if is_message_block:
            i += 2

        if is_message_block or is_standalone_str:
            text_parts, i, block_name, name_line_idx = _collect_text_block(lines, i, total)
            if text_parts:
                # 角色名占一个 seq
                if block_name is not None:
                    if name_line_idx is not None and seq in name_translations:
                        trans_name = name_translations[seq]
                        lines[name_line_idx] = json.dumps([trans_name], ensure_ascii=False) + '\n'
                    seq += 1

                # 对话文本占一个 seq
                if seq in translations:
                    trans = translations[seq]
                    trans_parts = trans.split('\\n')

                    # text_parts 里每个 'text' 占用 1 段，每个 'ruby' 占用 2 段（前文 + base）
                    # ruby 的 reading 不在译文里，注入时按原 reading 字符数填全角空格
                    cursor = 0
                    for p in text_parts:
                        if p[0] == 'text':
                            arg_idx = p[1]
                            new_val = trans_parts[cursor] if cursor < len(trans_parts) else ""
                            lines[arg_idx] = json.dumps([new_val], ensure_ascii=False) + '\n'
                            cursor += 1
                        elif p[0] == 'ruby':
                            r = p[1]
                            seg_prev = trans_parts[cursor] if cursor < len(trans_parts) else ""
                            seg_base = trans_parts[cursor + 1] if cursor + 1 < len(trans_parts) else ""
                            cursor += 2
                            # reading 填等量 \u3000 占位：
                            #   按原 reading 去掉 \u3000 后的"实际假名数"作为占位字符数
                            #   稀疏型 'な\u3000お\u3000や' (5 字符 / 3 假名) → 填 3 个 \u3000
                            #   紧凑型 'ななせ' (3 字符) → 填 3 个 \u3000
                            n_chars = len(r['orig_reading'].replace('\u3000', ''))
                            filler = '\u3000' * n_chars
                            lines[r['prev_arg_idx']] = json.dumps([seg_prev], ensure_ascii=False) + '\n'
                            lines[r['reading_arg_idx']] = json.dumps([filler], ensure_ascii=False) + '\n'
                            lines[r['base_arg_idx']] = json.dumps([seg_base], ensure_ascii=False) + '\n'

                seq += 1
        else:
            i += 1

    # 3. 写出新 op.txt
    with open(output_txt_path, 'w', encoding='utf-8-sig') as out:
        out.writelines(lines)

    return seq


if __name__ == "__main__":
    import argparse, os, glob

    ap = argparse.ArgumentParser(
        description="Silky MES translate.txt + op.txt -> 新 op.txt (单文件 或 目录批处理)"
    )
    ap.add_argument("op_txt", help="原始 *.op.txt (单文件 或 目录)")
    ap.add_argument("translate_txt", help="译文 translate.txt (单文件 或 目录)")
    ap.add_argument("output_op_txt", help="新 op.txt (单文件 或 输出目录)")
    ap.add_argument("--pattern", default="*.op.txt",
                    help="目录模式下匹配 op.txt 的通配 (default: *.op.txt)")
    args = ap.parse_args()

    def _strip_ext(name, exts):
        for e in exts:
            if name.lower().endswith(e.lower()):
                return name[:-len(e)]
        return os.path.splitext(name)[0]

    if os.path.isdir(args.op_txt):
        if not os.path.isdir(args.translate_txt):
            raise SystemExit("批处理模式下 translate_txt 也必须是目录")
        os.makedirs(args.output_op_txt, exist_ok=True)
        files = sorted(glob.glob(os.path.join(args.op_txt, args.pattern)))
        print(f"[batch] {len(files)} 个 op.txt 注入 -> {args.output_op_txt}")
        total_entries = 0
        missing = []
        for f in files:
            base = _strip_ext(os.path.basename(f), ['.op.txt'])
            tr = os.path.join(args.translate_txt, base + '.translate.txt')
            if not os.path.isfile(tr):
                missing.append(base)
                continue
            out = os.path.join(args.output_op_txt, base + '.op.txt')
            n = import_text(f, tr, out)
            total_entries += n
            print(f"  [+] {base}: {n} entries injected")
        if missing:
            print(f"[!] {len(missing)} 个文件缺失对应 translate.txt: {missing[:5]}{'...' if len(missing)>5 else ''}")
        print(f"[batch] 完成 {len(files) - len(missing)} 个文件, 共 {total_entries} 条")
    else:
        n = import_text(args.op_txt, args.translate_txt, args.output_op_txt)
        print(f"[+] injected {n} entries: {args.translate_txt} -> {args.output_op_txt}")
