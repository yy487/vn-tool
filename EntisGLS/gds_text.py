#!/usr/bin/env python3
"""
GDS 脚本文本提取/导入工具
适用引擎: EntisGLS / VIST (EScriptV2)
格式: UTF-16LE 明文脚本 (.gds)

用法:
  提取: python gds_text.py extract <input.gds> [output.txt]
  导入: python gds_text.py inject  <orig.gds> <trans.txt> [output.gds]
  批量: python gds_text.py extract_dir <gds_dir> [txt_dir]
        python gds_text.py inject_dir  <gds_dir> <txt_dir> [out_dir]

提取格式 (每条文本):
  ●<编号>|<行号>|<类型>|<角色名>
  <原文>
  (空行分隔)

类型说明:
  name     = 角色名 【xxx】
  dialogue = 台词/内心独白 (含 @ps 等控制码)
  narration= 旁白/叙述
  choice   = 选择肢 "xxx";
  title    = 标题文字 (\\S...\\NS)
"""

import re
import sys
import os
from pathlib import Path


def read_gds(filepath):
    """读取GDS文件返回 (文本, 编码名)"""
    with open(filepath, 'rb') as f:
        raw = f.read()
    # UTF-16LE needs even byte count; pad if odd
    if len(raw) % 2 == 1:
        raw = raw + b'\x00'
    # UTF-16LE with BOM
    if raw[:2] == b'\xff\xfe':
        return raw.decode('utf-16-le'), 'utf-16-le-bom'
    # Try UTF-16LE without BOM (check for null bytes typical of UTF-16)
    if len(raw) >= 4 and raw[1] == 0:
        try:
            return raw.decode('utf-16-le'), 'utf-16-le'
        except UnicodeDecodeError:
            pass
    # Try Shift-JIS (common for Japanese game scripts)
    try:
        return raw.decode('cp932'), 'cp932'
    except UnicodeDecodeError:
        pass
    # Fallback UTF-8
    return raw.decode('utf-8', errors='replace'), 'utf-8'


def write_gds(filepath, text, encoding='utf-16-le-bom'):
    """写入GDS文件，保持原始编码"""
    with open(filepath, 'wb') as f:
        if encoding == 'utf-16-le-bom':
            f.write(text.encode('utf-16-le'))
        elif encoding == 'utf-16-le':
            # Strip BOM if present then encode
            if text.startswith('\ufeff'):
                text = text[1:]
            f.write(text.encode('utf-16-le'))
        elif encoding == 'cp932':
            if text.startswith('\ufeff'):
                text = text[1:]
            f.write(text.encode('cp932', errors='replace'))
        else:
            if text.startswith('\ufeff'):
                text = text[1:]
            f.write(text.encode('utf-8'))


# ─── Patterns ───

RE_NAME = re.compile(r'^【(.+?)】$')
RE_PS = re.compile(r'@ps\([^)]*\)>')
RE_TALK = re.compile(r'@Talk\([^)]*\)')
RE_CHOICE = re.compile(r'^\t"(.+?)";$')
RE_TITLE = re.compile(r'\\S.*?\\NS')
RE_COMMENT = re.compile(r'^@;')
RE_CODE_START = re.compile(r'^@\{')
RE_CODE_LINE = re.compile(r'^@[A-Z]|^\t[a-zA-Z_]|^\t\t|^}')
RE_LABEL = re.compile(r'^#\s')
RE_GOTO = re.compile(r'^@goto\s')


def is_displayable(line):
    """判断一行是否包含可显示的游戏文本"""
    s = line.strip()
    if not s:
        return False
    # BOM
    if s.startswith('\ufeff'):
        return False
    # Comment
    if s.startswith('@;'):
        return False
    # Code block delimiters
    if s in ('{', '}', '}>'):
        return False
    if s.startswith('@{') or s.startswith('@}'):
        return False
    # Label / section header
    if s.startswith('#'):
        return False
    # Indented code (tab-indented lines that aren't quoted choices)
    # Must check raw line, not stripped
    if line.startswith('\t') and not RE_CHOICE.match(s):
        return False
    # Pure @ commands (no Japanese text before @)
    if s.startswith('@') and not RE_NAME.match(s):
        return False
    # goto
    if RE_GOTO.match(s):
        return False
    return True


def extract_text(gds_text):
    """从GDS脚本提取可翻译文本

    Returns: list of (index, line_no, type, name, text)
    """
    lines = gds_text.split('\r\n')
    if not lines[-1]:
        lines = lines[:-1]

    entries = []
    idx = 0
    current_name = ""
    in_code_block = False
    in_choice_block = False

    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()

        # Track code blocks @{...}> and bare choice blocks {...}
        if s.startswith('@{'):
            in_code_block = True
            i += 1
            continue
        if s == '{':
            # Bare { = choice block (after # label)
            in_code_block = True
            in_choice_block = True
            i += 1
            continue
        if s == '}' or s == '}>':
            in_code_block = False
            in_choice_block = False
            i += 1
            continue

        # Inside code block: check for choice strings
        if in_code_block or in_choice_block:
            m = RE_CHOICE.match(line.rstrip())
            if m:
                entries.append((idx, i+1, 'choice', '', m.group(1)))
                idx += 1
            i += 1
            continue

        # Character name: 【xxx】
        m = RE_NAME.match(s)
        if m:
            name = m.group(1)
            entries.append((idx, i+1, 'name', '', name))
            idx += 1
            current_name = name
            i += 1
            continue

        # Skip non-displayable lines (before title check, so @; comments are filtered)
        if not is_displayable(line):
            if not s:
                pass
            i += 1
            continue

        # Title text: \S...\NS (only on displayable lines)
        if '\\S' in s and '\\NS' in s:
            entries.append((idx, i+1, 'title', '', line.rstrip()))
            idx += 1
            i += 1
            continue

        # Displayable text: collect multi-line blocks
        # A text block = consecutive displayable lines until @ps()> or blank
        text_lines = []
        block_start = i
        while i < len(lines):
            cl = lines[i]
            cs = cl.strip()

            if not cs:
                break
            if cs.startswith('@') and not cs.startswith('@ps') and not cs.startswith('@Talk'):
                # Hit a command line
                break
            if cs.startswith('#') or cs.startswith('\t') or cs.startswith('}'):
                break
            if RE_NAME.match(cs):
                break

            text_lines.append(cl.rstrip())
            i += 1

            # If this line has @ps()>, it ends the block
            if '@ps' in cs:
                break

        if text_lines:
            full_text = '\r\n'.join(text_lines)
            ttype = 'dialogue' if current_name else 'narration'
            entries.append((idx, block_start+1, ttype, current_name, full_text))
            idx += 1

            # After a text block with @ps, check if next is also text
            # (not a new name) - means it continues as narration
            # Don't reset current_name here
        else:
            i += 1

    return entries


def strip_controls(text):
    """从文本中剥离控制码，返回纯净文本供翻译"""
    import re
    s = text
    # Remove @ps(...)>
    s = re.sub(r'@ps\([^)]*\)>', '', s)
    # Remove @Talk(...)
    s = re.sub(r'@Talk\([^)]*\)', '', s)
    # Remove \S+N prefix and \NS suffix (keep inner text)
    s = re.sub(r'\\S\+?\d*', '', s)
    s = s.replace('\\NS', '')
    # Normalize CRLF to LF for clean output
    s = s.replace('\r\n', '\n')
    # Remove leading fullwidth spaces per line (display indentation)
    lines = s.split('\n')
    lines = [l.lstrip('\u3000') for l in lines]
    s = '\n'.join(lines)
    return s.strip()


def format_extracted(entries, filename=""):
    """格式化提取结果为GalTransl JSON"""
    import json
    records = []
    for idx, line_no, ttype, name, text in entries:
        if ttype == 'name':
            continue  # 角色名在dialogue的name字段处理，不单独输出
        clean = strip_controls(text)
        if not clean:
            continue
        rec = {
            "name": name if name else None,
            "message": clean,
            "message_id": line_no,
        }
        records.append(rec)
    return json.dumps(records, ensure_ascii=False, indent=4)


def parse_translation(trans_text):
    """解析GalTransl JSON翻译文件，返回 {message_id: (name, translated_message)}"""
    import json
    data = json.loads(trans_text)
    translations = {}
    for rec in data:
        mid = rec.get("message_id")
        msg = rec.get("message", "")
        name = rec.get("name")
        if mid is not None and msg:
            translations[mid] = (name, msg)
    return translations


def inject_text(gds_text, entries, translations):
    """将翻译注入GDS脚本

    只替换有翻译的条目。translations按message_id(行号)索引。
    翻译文本是纯净的（无控制码），导入时还原原文的控制码。
    """
    import re as _re
    lines = gds_text.split('\r\n')

    # Build line_no -> entry mapping
    entry_by_line = {}
    for idx, line_no, ttype, name, orig_text in entries:
        entry_by_line[line_no] = (idx, ttype, name, orig_text)

    # Apply translations (from bottom to top to preserve line numbers)
    for line_no in sorted(translations.keys(), reverse=True):
        if line_no not in entry_by_line:
            continue
        idx, ttype, name, orig_text = entry_by_line[line_no]
        trans_name, trans_msg = translations[line_no]
        line_idx = line_no - 1

        if ttype == 'name':
            val = trans_name if trans_name else trans_msg
            if val:
                lines[line_idx] = f'【{val}】'

        elif ttype == 'choice':
            old_line = lines[line_idx]
            m = RE_CHOICE.match(old_line.rstrip())
            if m:
                indent = old_line[:len(old_line) - len(old_line.lstrip())]
                lines[line_idx] = f'{indent}"{trans_msg}";'

        elif ttype == 'title':
            orig_s = orig_text.rstrip()
            # Extract prefix: \S+N + any fullwidth space padding
            s_prefix_m = _re.match(r'(\\S\+?\d*[\u3000]*)', orig_s)
            ps_suffix_m = _re.search(r'(\\NS@ps\([^)]*\)>)$', orig_s)
            prefix = s_prefix_m.group(1) if s_prefix_m else '\\S'
            suffix = ps_suffix_m.group(1) if ps_suffix_m else '\\NS@ps()>'
            lines[line_idx] = f'{prefix}{trans_msg}{suffix}'

        else:
            # dialogue/narration: restore control codes from original
            # CRITICAL: must preserve exact line count to avoid label offset corruption
            orig_lines = orig_text.split('\r\n')
            span = len(orig_lines)
            trans_lines_raw = trans_msg.split('\n')

            # Force match original line count
            if len(trans_lines_raw) > span:
                # Too many lines: merge excess into last line
                merged = trans_lines_raw[:span-1] + ['\n'.join(trans_lines_raw[span-1:])]
                trans_lines_raw = merged
            elif len(trans_lines_raw) < span:
                # Too few lines: pad last translated line into first slot,
                # keep remaining original lines' structure with empty display text
                while len(trans_lines_raw) < span:
                    trans_lines_raw.append('')

            result_lines = []
            for ti in range(span):
                tl = trans_lines_raw[ti]
                orig_line = orig_lines[ti]
                # Leading fullwidth space
                lead = ''
                tmp = orig_line
                while tmp.startswith('\u3000'):
                    lead += '\u3000'
                    tmp = tmp[1:]
                # Trailing controls
                tail_m = _re.search(r'(@Talk\([^)]*\))?(@ps\([^)]*\)>)$', orig_line)
                tail = tail_m.group(0) if tail_m else ''
                if tl:
                    result_lines.append(f'{lead}{tl}{tail}')
                else:
                    # Empty translated line: keep original structure (lead + tail only)
                    result_lines.append(f'{lead}{tail}')

            lines[line_idx:line_idx + span] = result_lines

    return '\r\n'.join(lines)


# ─── CLI ───

def cmd_extract(gds_path, out_path=None):
    if out_path is None:
        out_path = os.path.splitext(gds_path)[0] + '.json'

    gds_text, enc = read_gds(gds_path)
    entries = extract_text(gds_text)
    formatted = format_extracted(entries, os.path.basename(gds_path))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(formatted)

    # Stats
    names = sum(1 for e in entries if e[2] == 'name')
    dialogue = sum(1 for e in entries if e[2] == 'dialogue')
    narration = sum(1 for e in entries if e[2] == 'narration')
    choices = sum(1 for e in entries if e[2] == 'choice')
    titles = sum(1 for e in entries if e[2] == 'title')

    print(f"  {os.path.basename(gds_path)}: {len(entries)} 条")
    print(f"    名前={names} 台詞={dialogue} 地文={narration} 選択={choices} 標題={titles}")
    print(f"  → {out_path}")


def cmd_inject(orig_path, trans_path, out_path=None):
    if out_path is None:
        out_path = os.path.splitext(orig_path)[0] + '_cn.gds'

    gds_text, enc = read_gds(orig_path)
    entries = extract_text(gds_text)

    with open(trans_path, 'r', encoding='utf-8') as f:
        trans_text = f.read()
    translations = parse_translation(trans_text)

    result = inject_text(gds_text, entries, translations)
    write_gds(out_path, result, enc)

    print(f"  翻译条目: {len(translations)}/{len(entries)}")
    print(f"  → {out_path}")


def cmd_extract_dir(gds_dir, out_dir=None):
    if out_dir is None:
        out_dir = gds_dir + '_text'
    os.makedirs(out_dir, exist_ok=True)
    files = sorted(Path(gds_dir).glob('*.gds'))
    print(f"批量提取: {len(files)} 个文件")
    total = 0
    for f in files:
        try:
            out = os.path.join(out_dir, f.stem + '.json')
            gds_text, enc = read_gds(str(f))
            entries = extract_text(gds_text)
            formatted = format_extracted(entries, f.name)
            with open(out, 'w', encoding='utf-8') as fout:
                fout.write(formatted)
            print(f"  {f.name}: {len(entries)} 条 → {f.stem}.json")
            total += len(entries)
        except Exception as e:
            print(f"  ✗ {f.name}: {e}")
    print(f"完成: {total} 条文本")


def cmd_inject_dir(gds_dir, txt_dir, out_dir=None):
    if out_dir is None:
        out_dir = gds_dir + '_cn'
    os.makedirs(out_dir, exist_ok=True)
    gds_files = sorted(Path(gds_dir).glob('*.gds'))
    print(f"批量导入: {len(gds_files)} 个文件")
    for gf in gds_files:
        tf = Path(txt_dir) / (gf.stem + '.json')
        if not tf.exists():
            tf = Path(txt_dir) / (gf.stem + '.txt')  # fallback
        if not tf.exists():
            # No translation, copy original
            out = os.path.join(out_dir, gf.name)
            with open(str(gf), 'rb') as fin:
                with open(out, 'wb') as fout:
                    fout.write(fin.read())
            continue
        out = os.path.join(out_dir, gf.name)
        gds_text, enc = read_gds(str(gf))
        entries = extract_text(gds_text)
        with open(str(tf), 'r', encoding='utf-8') as fin:
            translations = parse_translation(fin.read())
        result = inject_text(gds_text, entries, translations)
        write_gds(out, result, enc)
        print(f"  {gf.name}: {len(translations)}/{len(entries)} 条")
    print("完成")


def main():
    if len(sys.argv) < 3:
        print("GDS 脚本文本提取/导入工具")
        print("适用引擎: EntisGLS / VIST")
        print()
        print("用法:")
        print(f"  {sys.argv[0]} extract     <input.gds> [output.txt]")
        print(f"  {sys.argv[0]} inject      <orig.gds> <trans.txt> [output.gds]")
        print(f"  {sys.argv[0]} extract_dir <gds_dir> [txt_dir]")
        print(f"  {sys.argv[0]} inject_dir  <gds_dir> <txt_dir> [out_dir]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == 'extract':
        out = sys.argv[3] if len(sys.argv) > 3 else None
        cmd_extract(sys.argv[2], out)
    elif cmd == 'inject':
        if len(sys.argv) < 4:
            print("用法: inject <orig.gds> <trans.txt> [output.gds]")
            sys.exit(1)
        out = sys.argv[4] if len(sys.argv) > 4 else None
        cmd_inject(sys.argv[2], sys.argv[3], out)
    elif cmd == 'extract_dir':
        out = sys.argv[3] if len(sys.argv) > 3 else None
        cmd_extract_dir(sys.argv[2], out)
    elif cmd == 'inject_dir':
        if len(sys.argv) < 4:
            print("用法: inject_dir <gds_dir> <txt_dir> [out_dir]")
            sys.exit(1)
        out = sys.argv[4] if len(sys.argv) > 4 else None
        cmd_inject_dir(sys.argv[2], sys.argv[3], out)
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)


if __name__ == '__main__':
    main()
