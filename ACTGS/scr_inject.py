#!/usr/bin/env python3
"""
ACTGS 引擎 .scr 脚本文本注入工具
将翻译 JSON 注入回 arc.scr

用法: python scr_inject.py <ACTGS.exe> <arc.scr> <翻译JSON目录> [输出arc.scr] [编码]
  编码默认 cp932，汉化用 gbk
"""

import struct
import json
import os
import sys
import re

from scr_crypto import (
    auto_find_key, parse_archive, build_archive, encrypt_script,
)
from scr_extract import (
    PURE_COMMANDS, SEL_PREFIX_RE, INLINE_NAME_RE,
    has_japanese, is_pure_command,
)


FULLWIDTH_DIGITS = '０１２３４５６７８９'


def make_sel_prefix(n):
    """生成全角选项编号: 1→"１．", 10→"１０．" """
    fw = ''.join(FULLWIDTH_DIGITS[int(c)] for c in str(n))
    return fw + '．'


def to_fullwidth(orig, translated):
    """
    整段匹配策略: 把译文里连续的半角 ASCII 段作为整体跟原文比
    - 该段在原文中出现 → 保留半角 (如品牌名 PC、CD)
    - 该段在原文中未出现 → 整段转全角
    - 保护 \\n \\t 等转义序列
    """
    PLACEHOLDER = '\ue000'
    saved = []
    idx = 0
    result_chars = []
    while idx < len(translated):
        if translated[idx] == '\\' and idx + 1 < len(translated) and translated[idx+1].isalpha():
            marker = PLACEHOLDER + chr(0xE001 + len(saved))
            saved.append((marker, translated[idx:idx+2]))
            result_chars.append(marker)
            idx += 2
        else:
            result_chars.append(translated[idx])
            idx += 1
    protected = ''.join(result_chars)

    orig_cleaned = re.sub(r'\\[a-zA-Z]', '', orig)

    out = []
    i = 0
    n = len(protected)
    while i < n:
        cp = ord(protected[i])
        if 0x20 < cp < 0x7F or cp == 0x20:
            start = i
            while i < n:
                ccp = ord(protected[i])
                if 0x20 < ccp < 0x7F or ccp == 0x20:
                    i += 1
                else:
                    break
            raw_seg = protected[start:i]
            core = raw_seg.strip(' ')
            leading = raw_seg[:len(raw_seg) - len(raw_seg.lstrip(' '))]
            trailing = raw_seg[len(leading) + len(core):]

            if not core:
                out.append(raw_seg)
                continue

            if core in orig_cleaned:
                out.append(raw_seg)
            else:
                out.append(leading)
                for ch in core:
                    chp = ord(ch)
                    if chp == 0x20:
                        out.append('\u3000')
                    elif 0x20 < chp < 0x7F:
                        out.append(chr(chp + 0xFEE0))
                    else:
                        out.append(ch)
                out.append(trailing)
        else:
            out.append(protected[i])
            i += 1
    result = ''.join(out)

    for marker, esc in saved:
        result = result.replace(marker, esc)
    return result


# ============================================================
# 文本注入
# ============================================================
def inject_text(name, scr_bytes, translations, encoding='cp932'):
    text = scr_bytes.decode('cp932', errors='replace')
    lines = text.split('\r\n')
    new_lines = []
    basename = name.replace('.scr', '')
    text_id = 0
    i = 0
    replaced = 0

    # 预扫描: 为每个 def_sel 分配组内序号
    sel_group_counter = {}
    group_num = 0
    in_group = False
    for li, line in enumerate(lines):
        s = line.strip()
        if s.startswith('def_sel ') and has_japanese(s[8:]):
            if not in_group:
                in_group = True
                group_num = 0
            group_num += 1
            sel_group_counter[li] = group_num
        elif s and not s.startswith('vo') and not s.startswith(';') and \
                not s.startswith('def_selmes') and not s.startswith('def_sel'):
            in_group = False

    while i < len(lines):
        stripped = lines[i].strip()
        indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]

        # ---- def_sel ----
        if stripped.startswith('def_sel '):
            sel_text = stripped[8:]
            if has_japanese(sel_text):
                tid = f"{basename}/{text_id}/sel"
                group_n = sel_group_counter.get(i, 1)
                prefix = make_sel_prefix(group_n)
                if tid in translations:
                    tr_body = translations[tid]['message']
                    m = SEL_PREFIX_RE.match(tr_body)
                    if m: tr_body = tr_body[m.end():]
                    orig_m = SEL_PREFIX_RE.match(sel_text)
                    orig_body = sel_text[orig_m.end():] if orig_m else sel_text
                    tr_body = to_fullwidth(orig_body, tr_body)
                    new_lines.append(f"{indent}def_sel {prefix}{tr_body}")
                    replaced += 1
                else:
                    m = SEL_PREFIX_RE.match(sel_text)
                    body = sel_text[m.end():] if m else sel_text
                    new_lines.append(f"{indent}def_sel {prefix}{body}")
                text_id += 1
            else:
                new_lines.append(lines[i])
            i += 1; continue

        # ---- def_selmes ----
        if stripped.startswith('def_selmes ') and not stripped.startswith('def_selmes2'):
            sel_text = stripped[11:]
            if has_japanese(sel_text):
                tid = f"{basename}/{text_id}/selmes"
                if tid in translations:
                    tr_msg = to_fullwidth(sel_text, translations[tid]['message'])
                    new_lines.append(f"{indent}def_selmes {tr_msg}")
                    replaced += 1
                else:
                    new_lines.append(lines[i])
                text_id += 1
            else:
                new_lines.append(lines[i])
            i += 1; continue

        # ---- vo / vo2 ----
        if stripped.startswith('vo ') or stripped.startswith('vo2 '):
            new_lines.append(lines[i]); i += 1
            speaker = ""
            msg_lines = []
            msg_start = -1
            msg_end = -1
            speaker_line_idx = -1

            while i < len(lines):
                cur = lines[i].strip()
                if not cur:
                    new_lines.append(lines[i]); i += 1; continue
                if cur.startswith('msg2 '):
                    speaker = cur[5:].strip()
                    speaker_line_idx = len(new_lines)
                    new_lines.append(lines[i]); i += 1; continue
                if (cur.startswith('def_sel ') or
                    (cur.startswith('def_selmes ') and not cur.startswith('def_selmes2'))):
                    break
                if cur == 'ret': break
                if is_pure_command(cur): break
                if has_japanese(cur) or cur.startswith('「'):
                    if msg_start < 0: msg_start = len(new_lines)
                    msg_lines.append(cur)
                    new_lines.append(lines[i])
                    msg_end = len(new_lines)
                    i += 1; continue
                new_lines.append(lines[i]); i += 1; break

            if msg_lines:
                tid = f"{basename}/{text_id}"
                if tid in translations:
                    tr = translations[tid]
                    orig_msg = '\\n'.join(msg_lines)
                    tr_msg = to_fullwidth(orig_msg, tr['message'])

                    if speaker_line_idx >= 0 and tr.get('name'):
                        old_line = new_lines[speaker_line_idx]
                        sp_indent = old_line[:len(old_line) - len(old_line.lstrip())]
                        new_lines[speaker_line_idx] = f"{sp_indent}msg2 {tr['name']}"
                    elif speaker_line_idx < 0 and len(msg_lines) == 1:
                        orig_m = INLINE_NAME_RE.match(msg_lines[0])
                        if orig_m and tr.get('name'):
                            tr_msg = f"{tr['name']}{tr_msg}"

                    tr_lines = tr_msg.split('\\n')
                    orig_indent = ''
                    if msg_start < len(new_lines):
                        orig_line = new_lines[msg_start]
                        orig_indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
                    new_lines[msg_start:msg_end] = [f"{orig_indent}{tl}" for tl in tr_lines]
                    replaced += 1
                text_id += 1

            if i < len(lines) and lines[i].strip() == 'ret':
                new_lines.append(lines[i]); i += 1
            continue

        new_lines.append(lines[i]); i += 1

    result_bytes = '\r\n'.join(new_lines).encode(encoding, errors='replace')
    if result_bytes and result_bytes[0] != 0x4E:
        result_bytes = b'N' + result_bytes[1:]
    return result_bytes, replaced


# ============================================================
# 主程序
# ============================================================
def main():
    if len(sys.argv) < 4:
        print(f"用法: {sys.argv[0]} <ACTGS.exe> <arc.scr> <翻译JSON目录> [输出arc.scr] [编码]")
        print(f"  编码默认 cp932，汉化用 gbk")
        sys.exit(1)

    exe_path = sys.argv[1]
    arc_path = sys.argv[2]
    json_dir = sys.argv[3]
    out_path = sys.argv[4] if len(sys.argv) > 4 else 'arc_new.scr'
    encoding = sys.argv[5] if len(sys.argv) > 5 else 'cp932'

    print(f"搜索密钥: {exe_path}")
    key = auto_find_key(exe_path)
    if not key:
        print("错误: 未能从 EXE 中找到 XOR 密钥")
        sys.exit(1)
    print(f"密钥: {key.hex()} (长度 {len(key)})")

    print(f"解析档案: {arc_path}")
    scripts, header, header_encrypted = parse_archive(arc_path, key)
    print(f"脚本数量: {len(scripts)}" + (" (头部加密)" if header_encrypted else ""))
    print(f"输出编码: {encoding}")

    total_replaced = 0
    total_files = 0
    output_scripts = []

    for name, scr in scripts:
        json_path = os.path.join(json_dir, name.replace('.scr', '.json'))
        if os.path.exists(json_path):
            with open(json_path, 'r', encoding='utf-8') as f:
                entries = json.load(f)
            translations = {e['id']: e for e in entries}
            new_scr, replaced = inject_text(name, scr, translations, encoding)
            if replaced > 0:
                total_replaced += replaced
                total_files += 1
                print(f"  {name}: {replaced} 条替换")
            output_scripts.append((name, encrypt_script(new_scr, key)))
        else:
            output_scripts.append((name, encrypt_script(scr, key)))

    print(f"\n重建档案...")
    arc_data = build_archive(header, output_scripts, key, header_encrypted)
    with open(out_path, 'wb') as f:
        f.write(arc_data)

    print(f"完成! 共 {total_files} 个文件, {total_replaced} 条替换")
    print(f"输出: {out_path} ({len(arc_data)} 字节)")


if __name__ == '__main__':
    main()
