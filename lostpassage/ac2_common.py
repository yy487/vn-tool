#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ac2_common.py —— AdvSystem (LostPassage) 脚本处理共用模块
被 ac2_extract.py / ac2_inject.py 引用

文件格式: ac2_tool.py 解出的 CP932 明文脚本 (DATA\\SCRIPT\\*.TXT/*.STX)

行语法 (按"去前导 \\t 后"内容判别):
    [Command] args            # 引擎指令 (不翻译)
    //注释                     # 行注释 (不翻译)
    空行                       # (不翻译)
    名前\\t「内容」             # dialogue
    \\u3000叙述文 / 其他       # narration (不含 \\t)
    [Answer] 选项[, #目标]     # answer (要翻译, 跳转目标保留)

对话约定:
    前导 0~N 个 \\t (缩进); 首个 \\t 前是 name, 之后整段作为 text (保留「」等)
    H 场景故意不闭合引号、末尾带"（↑エコー）"等情况, 按整段处理, 不特殊识别

跳转目标 (#标签) 全部不翻译 —— 引擎用字符串匹配, 翻译长度变化零影响。
"""

import os
import re

SCRIPT_EXTS = ('.TXT', '.STX')
ENCODING = 'cp932'

# [Answer] 文本 [, #目标]
# 要求 "目标" 以 # 开头才认作跳转目标, 避免选项文本里的逗号误拆
RE_ANSWER = re.compile(r'^\[Answer\][ \t]+(.+?)(?:[ \t]*,[ \t]*(#\S.*?))?[ \t]*$')

# 指令行 (以 [Xxx] 开头, 大小写不限)
RE_CMD = re.compile(r'^\[[A-Za-z_][A-Za-z_0-9]*\]')


def classify_line(raw_line):
    """
    分类一行脚本文本 (不含行尾 \\r\\n)
    返回 (kind, info) 其中 kind ∈ {'dialogue','narration','answer',None}
    info 包含重建该行所需的全部结构信息:
        dialogue  : indent(前导\\t串), name, text
        narration : text   (整行, 无前导\\t不需要)
        answer    : text, suffix   (suffix 为 ', #目标' 或 '')
        None      : 不翻译 (info=None)
    """
    # 空行
    if raw_line == '':
        return None, None

    # 统一剥离前导 \t 计数
    stripped = raw_line.lstrip('\t')
    indent = raw_line[:len(raw_line) - len(stripped)]

    # 去前导 \t 后为空 (如单独 '\t' '\t\t' 行), 按空行跳过
    if stripped == '':
        return None, None

    # 注释
    if stripped.startswith('//'):
        return None, None

    # 指令行
    if stripped.startswith('['):
        # [Answer] 特殊处理
        if stripped.startswith('[Answer]'):
            m = RE_ANSWER.match(stripped)
            if m:
                text = m.group(1).rstrip()
                target = m.group(2)
                suffix = f', {target}' if target else ''
                return 'answer', {
                    'indent': indent,
                    'text': text,
                    'suffix': suffix,
                }
            # 格式异常的 [Answer] 按普通指令不翻译
            return None, None
        # 其他所有指令
        if RE_CMD.match(stripped):
            return None, None
        # 以 [ 开头但不是合法指令 (极少见), 当文本处理
        # 防御性: 不翻译 (避免误翻译)
        return None, None

    # 非指令非注释非空
    if '\t' in stripped:
        # 对话: name\ttext
        name, text = stripped.split('\t', 1)
        # 防御: name 或 text 任一为空, 按空行跳过 (极少见; e.g. 单独 "\t" 行)
        if not name or not text:
            return None, None
        return 'dialogue', {
            'indent': indent,
            'name': name,
            'text': text,
        }
    else:
        # 叙述
        return 'narration', {
            'indent': indent,
            'text': stripped,
        }


def iter_classified_lines(lines):
    """
    遍历整个脚本的行, 输出 (lineno_1based, kind, info)
    自动识别续行: 前一行末尾(去尾部空白)为 '\\' 的行, 视为指令参数续写
    —— 续行不翻译, kind=None。

    例: [DeclareWinMessage]  17, 351, ..., \\     ← 指令行
            0, 0, SPR_xxx, ..., \\                ← 续行
            +18, +12, 16, \\                      ← 续行
            26, 17                                ← 续行最末 (无 '\\', 但仍属续行组)
    """
    prev_line_continued = False
    for i, raw in enumerate(lines):
        lineno = i + 1
        if prev_line_continued:
            kind, info = None, None
        else:
            kind, info = classify_line(raw)
        yield lineno, kind, info
        prev_line_continued = raw.rstrip(' \t').endswith('\\')


def rebuild_line(kind, info, new_text):
    """
    根据分类和新文本, 重建原始行 (不含行尾 \\r\\n)
    new_text 为翻译后文本, 空字符串表示保留原文

    answer 特殊处理:
        - 形式① [Answer] X      (无显式目标) — 译后文本和跳转标签解耦:
          当文本被翻译为 Y 时, 重建为 [Answer] Y, #X_原日文
          因为引擎 [Select] 按 [Answer] 文本查找 [Label] #文本, 若选项被翻译而
          [Label] 仍是日文, 会导致 "ラベルが見つかりません" 错误
        - 形式② [Answer] X, #Y  (有显式目标) — 保留原 suffix 不变
    """
    text = new_text if new_text else info['text']
    if kind == 'dialogue':
        return f"{info['indent']}{info['name']}\t{text}"
    elif kind == 'narration':
        return f"{info['indent']}{text}"
    elif kind == 'answer':
        suffix = info['suffix']
        if not suffix:
            # 形式①: 若文本被翻译, 用原文作为显式跳转目标
            # 即使 new_text 为空, 也无害 (text == info['text'] 时 suffix 冗余但有效)
            if new_text and new_text != info['text']:
                suffix = f", #{info['text']}"
        return f"{info['indent']}[Answer] {text}{suffix}"
    raise ValueError(f'unknown kind: {kind}')


# ---------- 文件读写 ----------

def read_script(path):
    """
    读取脚本文件, 返回 (lines, eol)
        lines: 去尾部换行后的各行列表
        eol  : 该文件使用的行尾 ('\\r\\n' 或 '\\n')
    """
    with open(path, 'rb') as f:
        raw = f.read()
    text = raw.decode(ENCODING)
    # 检测行尾
    if '\r\n' in text:
        eol = '\r\n'
    else:
        eol = '\n'
    # splitlines 去掉所有行尾, 保留空行
    lines = text.split(eol)
    # 最后一个元素若为空, 表示原文件以 eol 结尾
    trailing_eol = False
    if lines and lines[-1] == '':
        lines.pop()
        trailing_eol = True
    return lines, eol, trailing_eol


def write_script(path, lines, eol, trailing_eol, encoding=ENCODING):
    """
    写入脚本文件, 保持原 eol 和末尾换行特性
    """
    text = eol.join(lines)
    if trailing_eol:
        text += eol
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'wb') as f:
        f.write(text.encode(encoding))


# ---------- 目录扫描 ----------

def iter_scripts(root):
    """
    递归遍历目录, yield (absolute_path, relative_path) 脚本文件对
    relative_path 使用 / 作为分隔符
    """
    root = os.path.abspath(root)
    for dirpath, _, filenames in os.walk(root):
        for fn in sorted(filenames):
            if not fn.upper().endswith(SCRIPT_EXTS):
                continue
            if fn == 'manifest.json':
                continue
            ap = os.path.join(dirpath, fn)
            rp = os.path.relpath(ap, root).replace(os.sep, '/')
            yield ap, rp


def copy_file(src, dst):
    """原样复制文件 (用于注入时未翻译文件的直通)"""
    os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
    with open(src, 'rb') as fi, open(dst, 'wb') as fo:
        fo.write(fi.read())
