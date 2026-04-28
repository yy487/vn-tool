"""silky_extract.py — Silky MES op.txt -> translate.txt 文本提取。

输入：silky_op.py 生成的 *.op.txt
输出：translate.txt（GalTransl 风格的双行格式 ◇/◆，◇ 行原文，◆ 行待翻译）

设计：
  * 不做注音特殊解析。每个对话块里所有 STR_CRYPT (0x0A) / STR_UNCRYPT (0x0B)
    字符串按出现顺序平铺，用 \\n 分隔在一个 ◇ 条目里。例如注音段：
      ◇0004◇『なあ、なんで何も言わないんだ、\\n \\nな　お　や\\n奈緒矢……』
    译者按顺序翻译这 4 段，import 时按相同顺序写回。段数必须一致。
  * 角色名 (PUSH_STR + PUSH 模式) 单独占一个 ◇/◆ 条目，标记为 ◇N◇name◇xxx。
    本游戏没用人名行，但保留逻辑兼容其他 silky 游戏。

CLI:
  python silky_extract.py <input.op.txt> <output.translate.txt>
"""

import json
import re

# ============================================================
# block 识别用的常量集合（从 silky_op 的 OP_TABLE 推导出来的标签）
# ============================================================

# 角色名块里出现的特殊 PUSH 数值（不同 silky 引擎变体可能不同）
_NAME_BLOCK_PUSH_VALS = frozenset([83886080, 167772160])

# 块内 op：扫到这些不结束当前对话块，跳过 (op + arg) 两行
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

# 块结束 op：扫到这些当前对话块结束
_BLOCK_END_OPCODES = frozenset([
    '#1-MESSAGE', '#1-JUMP', '#1-MSG_OFSETTER', '#1-SPEC_OFSETTER',
    '#1-1a', '#1-1b',
])

# STR_CRYPT (0x0A) 和 STR_UNCRYPT (0x0B) 都承载文本。
# 本游戏里 0x0A = 对话/注音内容，0x0B = 注音分隔符 (单字节空格)。
# 提取时统一收集，1:1 对应写回，保证字节级 round-trip。
_STR_OPCODE_LINES = frozenset(['#1-STR_CRYPT', '#1-STR_UNCRYPT'])


# ============================================================
# 辅助小工具
# ============================================================

def _is_label_or_free(line: str) -> bool:
    """是否是标签或 free bytes 行（#0- #2- #3）。"""
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


def _parse_json_first_int(arg_line: str) -> int:
    try:
        val = json.loads(arg_line)
        if isinstance(val, list) and len(val) > 0:
            return int(val[0])
    except (json.JSONDecodeError, IndexError, ValueError):
        pass
    return 0


# ============================================================
# 角色名块识别
# ============================================================

def _detect_name_block(lines, i, total):
    """检查 line i 是否是角色名块的 PUSH_STR。

    Pattern A: PUSH_STR[name] -> PUSH[83886080]  -> PUSH[...] -> 18[]
    Pattern B: PUSH_STR[name] -> PUSH[167772160] -> PUSH[...] -> 34[] -> PUSH[...] -> 18[]

    返回角色名字符串，或 None。
    """
    if i + 7 >= total:
        return None
    cl = lines[i].rstrip('\n')
    if cl != '#1-PUSH_STR':
        return None

    arg = _parse_json_str(lines[i + 1].rstrip('\n'))
    # 角色名必须是非 ASCII (避免误判路径字符串)
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

    # Pattern A
    if (i + 6 < total and
        lines[i + 4].rstrip('\n') == '#1-PUSH' and
        lines[i + 6].rstrip('\n') == '#1-18'):
        return arg

    # Pattern B
    if (i + 10 < total and
        lines[i + 4].rstrip('\n') == '#1-PUSH' and
        lines[i + 6].rstrip('\n') == '#1-34' and
        lines[i + 8].rstrip('\n') == '#1-PUSH' and
        lines[i + 10].rstrip('\n') == '#1-18'):
        return arg

    return None


# ============================================================
# 对话块收集
# ============================================================

def _try_match_ruby(lines, str_idx, total):
    """检查 str_idx (一个 #1-STR_CRYPT 行) 后面是否紧跟一个完整的 ruby 段。

    Pattern (相对偏移):
      str_idx + 0: #1-STR_CRYPT (前文)
      str_idx + 1: ["前文"]
      str_idx + 2: #1-TO_NEW_STRING
      str_idx + 3: [1]
      str_idx + 4: #1-STR_UNCRYPT
      str_idx + 5: [" "]
      str_idx + 6: #1-STR_CRYPT
      str_idx + 7: ["reading"]
      str_idx + 8: #1-RETURN
      str_idx + 9: []
      str_idx + 10: #1-STR_CRYPT
      str_idx + 11: ["base"]

    返回 (prev_arg_idx, sep_arg_idx, reading_arg_idx, base_arg_idx, prev_text, reading, base, end_idx)
    或 None。
    """
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
    prev_text = _parse_json_str(lines[str_idx + 1].rstrip('\n'))
    reading = _parse_json_str(lines[str_idx + 7].rstrip('\n'))
    base = _parse_json_str(lines[str_idx + 11].rstrip('\n'))
    return {
        'prev_arg_idx': str_idx + 1,
        'sep_arg_idx': str_idx + 5,
        'reading_arg_idx': str_idx + 7,
        'base_arg_idx': str_idx + 11,
        'prev_text': prev_text,
        'reading': reading,
        'base': base,
        'end_idx': str_idx + 12,  # 下一个待扫描位置
    }


def _collect_text_block(lines, start, total):
    """收集对话块所有 STR_CRYPT/STR_UNCRYPT 字符串，注音段合并为一条。

    text_parts 里每个元素：
      ('text', arg_line_idx, text_value)  - 普通字符串
      ('ruby', ruby_dict)                 - 注音整段 (含 4 个 arg 位置 + 3 个文本)
    """
    text_parts = []
    detected_name = None
    name_arg_line_idx = None
    i = start

    while i < total:
        cl = lines[i].rstrip('\n')

        # 角色名块？
        name = _detect_name_block(lines, i, total)
        if name is not None:
            detected_name = name
            name_arg_line_idx = i + 1
            i += 2
            continue

        if cl in _STR_OPCODE_LINES:
            # 看是不是 ruby 段开头
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


def _build_display_text(parts):
    """把 text_parts 拼成展示串。

    - 'text' part：直接用文本
    - 'ruby' part：展示为 "前文\\nbase"，注音 reading 不暴露给译者
      （注入时 reading 位置会自动填充等长全角空格）
    """
    out = []
    for p in parts:
        if p[0] == 'text':
            out.append(p[2])
        elif p[0] == 'ruby':
            r = p[1]
            out.append(r['prev_text'] + '\\n' + r['base'])
    return '\\n'.join(out)


# ============================================================
# 主入口
# ============================================================

def extract_text(opcode_txt_path: str, text_txt_path: str) -> int:
    """从 op.txt 提取所有 STR_CRYPT/STR_UNCRYPT 文本，写出 GalTransl 双行格式 translate.txt。

    输出格式：
      ◇0000◇原文
      ◆0000◆原文 (待翻译)
                          <- 空行分隔
      ◇0001◇下一条
      ...

    角色名占独立条目：
      ◇0001◇name◇角色名
      ◆0001◆name◆角色名

    返回总条目数。
    """
    with open(opcode_txt_path, 'r', encoding='utf-8-sig') as f:
        lines = f.readlines()

    total = len(lines)
    entries = []  # (block_name_or_None, text_parts)
    i = 0

    while i < total:
        line = lines[i].rstrip('\n')

        if line == '#1-MESSAGE':
            # 跳过 MESSAGE op + 它的 arg 行
            i += 2
            text_parts, i, block_name, _ = _collect_text_block(lines, i, total)
            if text_parts:
                entries.append((block_name, text_parts))

        elif line in _STR_OPCODE_LINES:
            text_parts, i, block_name, _ = _collect_text_block(lines, i, total)
            if text_parts:
                entries.append((block_name, text_parts))
        else:
            i += 1

    # 写出 ◇/◆ 双行格式
    seq = 0
    with open(text_txt_path, 'w', encoding='utf-8-sig') as out:
        for name, parts in entries:
            if name is not None:
                out.write(f'\u25c7{seq:04d}\u25c7name\u25c7{name}\n')
                out.write(f'\u25c6{seq:04d}\u25c6name\u25c6{name}\n')
                seq += 1
                out.write('\n')
            display = _build_display_text(parts)
            out.write(f'\u25c7{seq:04d}\u25c7{display}\n')
            out.write(f'\u25c6{seq:04d}\u25c6{display}\n')
            out.write('\n')
            seq += 1

    return seq


if __name__ == "__main__":
    import argparse, os, glob

    ap = argparse.ArgumentParser(
        description="Silky MES op.txt -> translate.txt (单文件 或 目录批处理)"
    )
    ap.add_argument("input", help="单个 *.op.txt 文件，或包含 *.op.txt 的目录")
    ap.add_argument("output", help="单文件输出路径，或输出目录")
    ap.add_argument("--pattern", default="*.op.txt",
                    help="目录模式下的 glob 通配符 (default: *.op.txt)")
    args = ap.parse_args()

    def _strip_ext(name, exts):
        for e in exts:
            if name.lower().endswith(e.lower()):
                return name[:-len(e)]
        return os.path.splitext(name)[0]

    if os.path.isdir(args.input):
        os.makedirs(args.output, exist_ok=True)
        files = sorted(glob.glob(os.path.join(args.input, args.pattern)))
        print(f"[batch] {len(files)} 个 op.txt -> {args.output}")
        total_entries = 0
        for f in files:
            base = _strip_ext(os.path.basename(f), ['.op.txt'])
            out = os.path.join(args.output, base + '.translate.txt')
            n = extract_text(f, out)
            total_entries += n
            print(f"  [+] {os.path.basename(f)}: {n} entries -> {os.path.basename(out)}")
        print(f"[batch] 完成 {len(files)} 个文件, 共 {total_entries} 条")
    else:
        n = extract_text(args.input, args.output)
        print(f"[+] extracted {n} entries: {args.input} -> {args.output}")
