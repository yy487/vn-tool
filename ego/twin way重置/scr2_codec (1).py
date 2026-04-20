#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scr2_codec.py — Studio e.go! 'SCR ' v1 脚本底层解析

跟 BSF1 是完全不同的引擎 (那个是 tw.exe / Daytalk 系列, magic='BSF1')。
本模块只负责扫描文本条目, 不做完整 VM 反汇编。

文件结构 (Ay_01.scr 实测):
    +0x00  'SCR '            magic
    +0x04  u32 version       = 1
    +0x08  u64 zero
    +0x10  u32 bc_end        bytecode 区结束偏移
    +0x14 .. bc_end          bytecode 区 (u8 opcode 流, 文本是嵌入 cstring)
    +bc_end ..               尾部表 (jump targets / labels), 不引用文本地址

文本嵌入模式 (在 bytecode 流里, 每段都以 \\0 结束):
    0x0A <speaker_cp932>\\0          speaker 设置
    0x01 0x01 0x0B <message>\\0      带说话人的台词
    0x01 0x0B <message>\\0           旁白

筛选规则: 必须含 CP932 双字节字符的 cstring 才算文本, 排除 'bg14a' 这类
ASCII 资源名参数。
"""
import struct

MAGIC = b'SCR '

# 顺序重要: 长 prefix 先匹配。不然 0x01 0x01 0x0b 会被 0x01 0x0b 错配,
# 0x02 0x01 0x0b 会被 0x01 0x0b 错配, 0x01 0x0b 会被 0x0b 错配。
PREFIXES = [
    (b'\x01\x01\x0b', 'message'),
    (b'\x02\x01\x0b', 'message'),    # 罕见变体, 31 例
    (b'\x01\x0b',     'narration'),
    (b'\x0b',         'message'),    # 裸 message, 105 例 (op01 那条就是这种)
    (b'\x0a',         'speaker'),
]


class ParseError(Exception):
    pass


def _is_jp_lead(b):
    return 0x81 <= b <= 0x9f or 0xe0 <= b <= 0xfc


def _has_jp(buf):
    return any(_is_jp_lead(b) for b in buf)


def parse_header(d: bytes) -> int:
    """返回 bc_end (bytecode 区结束偏移)."""
    if d[:4] != MAGIC:
        raise ParseError(f'bad magic: {d[:4]!r}')
    ver = struct.unpack_from('<I', d, 4)[0]
    if ver != 1:
        raise ParseError(f'unsupported version: {ver}')
    bc_end = struct.unpack_from('<I', d, 0x10)[0]
    if not (0x14 < bc_end <= len(d)):
        raise ParseError(f'bad bc_end: {bc_end:#x} (file size {len(d):#x})')
    return bc_end


def scan_entries(d: bytes):
    """扫描所有文本条目.

    返回 [(kind, content_start, content_end_excl), ...].
    content_start..content_end_excl 是 cstring "内容" (不含 prefix, 不含尾 \\0).
    原长度 = content_end_excl - content_start.
    kind ∈ {'speaker', 'message', 'narration'}.
    """
    bc_end = parse_header(d)
    out = []
    i = 0x14
    while i < bc_end:
        if d[i] == 0:
            i += 1
            continue
        j = d.find(b'\x00', i, bc_end)
        if j < 0:
            break
        chunk = d[i:j]
        if not _has_jp(chunk):
            i = j + 1
            continue
        kind = None
        content_start = None
        for pfx, name in PREFIXES:
            if chunk.startswith(pfx):
                kind = name
                content_start = i + len(pfx)
                break
        if kind is None:
            # 含日文但 prefix 不认识 → 跳过 (可能是别的指令的内联字符串)
            i = j + 1
            continue
        out.append((kind, content_start, j))
        i = j + 1
    return out


def extract_to_json(d: bytes):
    """把字节流转成 GalTransl 风格 JSON 条目列表.

    name 不做"持续继承": 只有当一条 message 紧邻前面 (中间无其它 message)
    出现过一个 speaker 时, 才把那个 speaker 当作这条的 name。
    一个 speaker 只服务于"下一条 message", 用完即清, 不继承到再下一条。
    """
    entries = scan_entries(d)
    pending_speaker = None
    result = []
    tid = 0
    for kind, s, e in entries:
        text = d[s:e].decode('cp932')
        if kind == 'speaker':
            pending_speaker = text
            continue
        item = {
            'id': tid,
            'pos': f'0x{s:x}',
            'len': e - s,
        }
        if kind == 'message' and pending_speaker is not None:
            item['name'] = pending_speaker
        # narration 永远不带 name
        item['message'] = text
        result.append(item)
        tid += 1
        pending_speaker = None  # 用完清除
    return result
