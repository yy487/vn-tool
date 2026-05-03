#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI5WIN 文本规范化共用模块。

注意：scan_chars.py、hanzi_replacer.py、ai5win_mes_inject.py 必须共用同一套
normalize_text，否则会出现“扫描进字库的字符”和“实际注入的字符”不一致。
"""

# 常见标点规范化：尽量让正文全部走双字节 CP932 字符。
_PUNCT_MAP = {
    ' ': '　',
    '“': '「', '”': '」',
    '‘': '『', '’': '』',
    '«': '「', '»': '」',
    '…': '…',
    '—': '―', '－': 'ー',
    '~': '～',
}


def ascii_to_fullwidth_char(c: str) -> str:
    """ASCII 可打印字符转全角。空格转全角空格。"""
    if c == ' ':
        return '　'
    if '!' <= c <= '~':
        return chr(ord(c) - 0x21 + 0xFF01)
    return c


def normalize_text(s: str, *, ascii_to_fullwidth: bool = True) -> str:
    """规范化译文。

    默认行为：
    - 半角空格 -> 全角空格
    - 半角 ASCII 可打印字符 -> 全角
    - 中英文引号等常见标点 -> 日式/全角标点
    - 换行保留为 \n，不参与全角化
    """
    out = []
    for c in s:
        if c == '\n':
            out.append(c)
            continue
        c = _PUNCT_MAP.get(c, c)
        if ascii_to_fullwidth:
            c = ascii_to_fullwidth_char(c)
        out.append(c)
    return ''.join(out)
