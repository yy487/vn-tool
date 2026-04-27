# -*- coding: utf-8 -*-
"""
te_codec.py — Lapis ($TAMdatas) .te 文件结构 codec

提供底层的文件结构解析/构建能力，不涉及翻译语义。
extract 和 inject 工具共用此模块。

文件布局（已确认）：
  [0x00]  $TAMdatas\\0\\0\\0               12B magic
  [0x0C]  u32  code_size
  [0x10]  u32  text_size
  [0x14]  u32  ??? count
  [0x18]  u32  tail_size
  [0x1C..0x3B]  其他 metadata
  [0x3C]  code section                VM 字节码, 4B-aligned = (u8 opcode, u24 value)
          value 若指向 text, 编码为 (text_offset << 4)
  [...]   marker = 00 F0 FF FF         4B 分界, 独立于 code_size
  [...]   text section                 SJIS 文本 + @XXX 标签 + 内嵌控制码
  [...]   tail section                 跨文件引用表
"""
import struct
import re

HDR_SIZE = 0x3C
MAGIC = b'$TAMdatas\0\0\0'
MARKER = b'\x00\xf0\xff\xff'


# ============================================================
# 底层 parse / build
# ============================================================
def parse_te(data: bytes) -> dict:
    """将 .te 文件拆成结构化 dict，不做任何修改。"""
    if data[:12] != MAGIC:
        raise ValueError(f'bad magic: {data[:12]!r}')
    code_size = struct.unpack_from('<I', data, 0x0C)[0]
    text_size = struct.unpack_from('<I', data, 0x10)[0]
    u14 = struct.unpack_from('<I', data, 0x14)[0]
    tail_size = struct.unpack_from('<I', data, 0x18)[0]

    code_start = HDR_SIZE
    code_end = code_start + code_size
    marker_off = code_end
    text_start = marker_off + 4
    text_end = text_start + text_size
    tail_start = text_end
    tail_end = tail_start + tail_size

    if data[marker_off:marker_off + 4] != MARKER:
        raise ValueError(f'marker mismatch @0x{marker_off:x}: '
                         f'got {data[marker_off:marker_off+4].hex()}')
    if tail_end != len(data):
        raise ValueError(f'total size mismatch: expected 0x{tail_end:x}, '
                         f'got 0x{len(data):x}')

    return dict(
        header=bytes(data[:HDR_SIZE]),
        code=bytes(data[code_start:code_end]),
        text=bytes(data[text_start:text_end]),
        tail=bytes(data[tail_start:tail_end]),
        code_size=code_size,
        text_size=text_size,
        tail_size=tail_size,
        u14=u14,
        text_start_in_file=text_start,
    )


def build_te(header: bytes, code: bytes, text: bytes, tail: bytes) -> bytes:
    """将各 section 重组为完整 .te 文件；自动同步 header 中的 size 字段。

    ⚠ 调用者负责保证 code 段已修正好所有引用（用 remap_code_refs）。
    """
    if len(header) != HDR_SIZE:
        raise ValueError(f'header must be {HDR_SIZE} bytes, got {len(header)}')
    hdr = bytearray(header)
    struct.pack_into('<I', hdr, 0x0C, len(code))
    struct.pack_into('<I', hdr, 0x10, len(text))
    struct.pack_into('<I', hdr, 0x18, len(tail))
    return bytes(hdr) + code + MARKER + text + tail


# ============================================================
# Code section 引用扫描与修正（变长注入核心）
# ============================================================
def iter_code_refs(code: bytes, text_size: int):
    """遍历 code 段，yield 所有指向 text 段的引用点。

    每 4 字节 = (u8 opcode, u24 value)。
    若 (value >> 4) < text_size，认为是对 text 段的引用。

    yield: dict(code_off, opcode, raw_val, text_off, low_bits)
    """
    for i in range(0, len(code) - 3, 4):
        w = struct.unpack_from('<I', code, i)[0]
        opcode = w & 0xFF
        raw_val = (w >> 8) & 0xFFFFFF
        text_off = raw_val >> 4
        low_bits = raw_val & 0xF
        if text_off < text_size:
            yield dict(
                code_off=i,
                opcode=opcode,
                raw_val=raw_val,
                text_off=text_off,
                low_bits=low_bits,
            )


def remap_code_refs(code: bytes, text_size_old: int, offset_map: dict) -> bytes:
    """根据 offset_map 修正 code 段中所有指向 text 的引用。

    参数
    ----
    code : 原 code 段
    text_size_old : 原 text 段大小（用来筛选引用）
    offset_map : {old_text_offset: new_text_offset}

    返回：修正后的 code 段字节串（长度不变）
    """
    out = bytearray(code)
    missing = []
    for ref in iter_code_refs(code, text_size_old):
        old = ref['text_off']
        if old not in offset_map:
            missing.append(old)
            continue
        new = offset_map[old]
        new_raw = (new << 4) | ref['low_bits']
        if new_raw > 0xFFFFFF:
            raise ValueError(
                f'new text offset 0x{new:x} 太大, 超过 u24 范围'
            )
        w = (new_raw << 8) | ref['opcode']
        struct.pack_into('<I', out, ref['code_off'], w)
    if missing:
        raise ValueError(
            f'{len(missing)} 个 code 引用在 offset_map 中找不到: '
            f'{[hex(x) for x in missing[:10]]}...'
        )
    return bytes(out)


def collect_ref_targets(code: bytes, text_size: int) -> set:
    """收集 code 段所有指向 text 的目标偏移（去重）。"""
    return {ref['text_off'] for ref in iter_code_refs(code, text_size)}


# ============================================================
# Text section 扫描工具
# ============================================================
def _is_hex(c: int) -> bool:
    return (0x30 <= c <= 0x39) or (0x41 <= c <= 0x46) or (0x61 <= c <= 0x66)


def find_labels(text: bytes) -> list:
    """返回所有 @XXX label 在 text 段内的偏移列表。

    判据：前一字节为 \\0, 当前字节为 @, 后 3 字节为 hex digits。
    """
    labels = []
    i = 0
    while i < len(text) - 4:
        if (text[i] == 0x40 and i > 0 and text[i - 1] == 0x00
                and _is_hex(text[i + 1]) and _is_hex(text[i + 2])
                and _is_hex(text[i + 3])):
            labels.append(i)
            i += 4
            continue
        i += 1
    return labels


def sjis_runs(chunk: bytes) -> list:
    """将字节块切分为合法可打印 SJIS 片段序列。

    返回 [(offset_in_chunk, bytes), ...]
    合法字节：
      - ASCII 可打印 0x20..0x7E
      - SJIS 双字节 0x81..0x9F/0xE0..0xFC + 0x40..0xFC (除 0x7F)
    """
    runs = []
    i = 0
    cs = None
    n = len(chunk)
    while i < n:
        b = chunk[i]
        if 0x20 <= b <= 0x7E:
            if cs is None:
                cs = i
            i += 1
        elif (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC):
            if i + 1 >= n:
                if cs is not None:
                    runs.append((cs, chunk[cs:i]))
                    cs = None
                break
            b2 = chunk[i + 1]
            if (0x40 <= b2 <= 0xFC) and b2 != 0x7F:
                if cs is None:
                    cs = i
                i += 2
            else:
                if cs is not None:
                    runs.append((cs, chunk[cs:i]))
                    cs = None
                i += 1
        else:
            if cs is not None:
                runs.append((cs, chunk[cs:i]))
                cs = None
            i += 1
    if cs is not None:
        runs.append((cs, chunk[cs:]))
    return runs


# ============================================================
# 选项块识别
# ============================================================
# 好感度标记：\\u3000(全角空格) + 1个全角字符 + ＋(SJIS 81 7B) 或 －(SJIS 81 7D)
AFFECTION_RE = re.compile('\u3000.[\uff0b\uff0d]')


def detect_choice_block(runs):
    """从一个 label 的 SJIS runs 列表判断是否为选项块。

    特征（基于 0610.te@22D 和 0611.te@055 两个样本）：
      - runs[0]: 以 '//$' 开头的装饰题目
      - runs[1]: 纯题目
      - runs[2]: 选项串（含 '|'，可能含好感度标记）
      - runs[3]: 与 runs[1] byte-identical（题目副本）
      - runs[4]: 选项串（与 runs[2] 去好感度标记后一致）

    返回 dict 或 None。
    """
    if len(runs) < 5:
        return None
    try:
        r0 = runs[0][1].decode('cp932')
        r2 = runs[2][1].decode('cp932')
        r4 = runs[4][1].decode('cp932')
    except UnicodeDecodeError:
        return None

    if not r0.startswith('//$'):
        return None
    # 题目副本应一致（byte-level）
    if runs[1][1] != runs[3][1]:
        return None
    # 选项串应含 '|'
    if '|' not in r2 or '|' not in r4:
        return None
    return dict(
        deco_title_idx=0,
        inner_title_idx=1,
        inner_opts_idx=2,
        shown_title_idx=3,
        shown_opts_idx=4,
    )


def parse_affection_marks(options_str: str) -> list:
    """从带好感度标记的选项串（按 | 拆）中提取每个选项的标记。

    返回 [str or '', ...]，每个元素对应一个选项末尾的标记（无则 ''）。
    例如 "外で転んだ…\\u3000優＋|いきなり男..." →
      ['\\u3000優＋', '', '']
    """
    parts = options_str.split('|')
    marks = []
    for part in parts:
        m = AFFECTION_RE.search(part)
        if m and m.end() == len(part):
            marks.append(m.group())
        else:
            marks.append('')
    return marks


def strip_affection_marks(options_str: str) -> str:
    """去除选项串里所有好感度标记。"""
    parts = options_str.split('|')
    cleaned = [AFFECTION_RE.sub('', p) for p in parts]
    return '|'.join(cleaned)


def apply_affection_marks(clean_options_str: str, marks: list) -> str:
    """把好感度标记追加回翻译后的选项串。

    clean_options_str: 翻译后（或去标记后）的选项串，按 | 拆分
    marks: 每个选项对应的标记（len 必须与拆分数相同）
    """
    parts = clean_options_str.split('|')
    if len(parts) != len(marks):
        raise ValueError(f'选项数不匹配: {len(parts)} vs {len(marks)}')
    return '|'.join(p + m for p, m in zip(parts, marks))


# ============================================================
# Tail section  (本地章节入口表)
# ============================================================
# 布局:
#   [+0x00]  u32 = 4                    常量 tag
#   [+0x04]  u32 * N  章节入口偏移 (指向本文件 text 段内)
#   [+?]    filename\\0 entry1\\0 entry2\\0 ... entryN\\0
#
# N = (字符串池里字符串总数 - 1); 字符串池第一个是本文件名。
# 这些偏移在变长注入时**也必须**同步更新。

def parse_tail(tail: bytes, text_size: int) -> dict:
    """解析 tail 段。返回 {type_tag, entry_offsets, filename_bytes, entry_name_bytes}。

    注意：字符串保留为原始 bytes（不做 SJIS 解码）以保证 byte-identical round-trip。
    获取可读字符串请用 .decode('cp932', errors='replace')。
    """
    if len(tail) == 0:
        return dict(type_tag=None, entry_offsets=[],
                    filename_bytes=b'', entry_name_bytes=[])

    type_tag = struct.unpack_from('<I', tail, 0)[0]

    # 找字符串池起点：从 +4 每 4 字节扫，第一个 >= text_size 的 dword 视为字符串池
    strs_start = len(tail)
    off = 4
    while off + 4 <= len(tail):
        v = struct.unpack_from('<I', tail, off)[0]
        if v >= text_size:
            strs_start = off
            break
        off += 4

    n_entries = (strs_start - 4) // 4
    entry_offsets = [
        struct.unpack_from('<I', tail, 4 + i * 4)[0]
        for i in range(n_entries)
    ]

    # 字符串池，NUL 分隔 (保留原始 bytes)
    raw_strs = tail[strs_start:].split(b'\0')
    strs = [s for s in raw_strs if s]
    filename_bytes = strs[0] if strs else b''
    entry_name_bytes = strs[1:]

    return dict(
        type_tag=type_tag,
        entry_offsets=entry_offsets,
        filename_bytes=filename_bytes,
        entry_name_bytes=entry_name_bytes,
    )


def build_tail(type_tag, entry_offsets: list,
               filename_bytes: bytes, entry_name_bytes: list) -> bytes:
    """按解析结构反向构建 tail 字节串。"""
    out = bytearray()
    out += struct.pack('<I', type_tag if type_tag is not None else 4)
    for off in entry_offsets:
        out += struct.pack('<I', off)
    out += filename_bytes + b'\0'
    for name in entry_name_bytes:
        out += name + b'\0'
    return bytes(out)


def remap_tail_refs(tail: bytes, text_size_old: int, offset_map: dict) -> bytes:
    """根据 offset_map 修正 tail 段的章节入口偏移。"""
    if len(tail) == 0:
        return tail
    parsed = parse_tail(tail, text_size_old)
    new_offs = []
    missing = []
    for old in parsed['entry_offsets']:
        if old in offset_map:
            new_offs.append(offset_map[old])
        else:
            missing.append(old)
            new_offs.append(old)
    if missing:
        raise ValueError(
            f'{len(missing)} 个 tail 入口偏移在 offset_map 中找不到: '
            f'{[hex(x) for x in missing[:10]]}...'
        )
    return build_tail(parsed['type_tag'], new_offs,
                      parsed['filename_bytes'], parsed['entry_name_bytes'])


def collect_tail_ref_targets(tail: bytes, text_size: int) -> set:
    """收集 tail 中所有指向 text 的目标偏移。"""
    if len(tail) == 0:
        return set()
    return set(parse_tail(tail, text_size)['entry_offsets'])


def validate_tail_refs(tail: bytes, text_size: int) -> list:
    """调试用：返回 tail 内所有 u32 值落在 text 范围内的位置。"""
    suspicious = []
    for i in range(0, len(tail) - 3, 4):
        v = struct.unpack_from('<I', tail, i)[0]
        if 0 < v < text_size:
            suspicious.append((i, v))
    return suspicious


# ============================================================
# 自测
# ============================================================
if __name__ == '__main__':
    import sys
    from pathlib import Path

    if len(sys.argv) < 2:
        print('usage: python te_codec.py <file.te>')
        sys.exit(1)

    fn = sys.argv[1]
    data = Path(fn).read_bytes()
    p = parse_te(data)
    print(f'file: {fn}')
    print(f'  code: {p["code_size"]:#x} bytes')
    print(f'  text: {p["text_size"]:#x} bytes')
    print(f'  tail: {p["tail_size"]:#x} bytes')
    print(f'  text starts at file offset 0x{p["text_start_in_file"]:x}')

    labels = find_labels(p['text'])
    print(f'  labels: {len(labels)}')

    refs = list(iter_code_refs(p['code'], p['text_size']))
    ref_targets = {r['text_off'] for r in refs}
    label_set = set(labels)
    ref_to_labels = sum(1 for t in ref_targets if t in label_set)
    print(f'  code refs to text: {len(refs)} total, '
          f'{len(ref_targets)} unique targets')
    print(f'    - pointing to labels: {ref_to_labels}')
    print(f'    - pointing to other text: {len(ref_targets) - ref_to_labels}')

    suspicious = validate_tail_refs(p['tail'], p['text_size'])
    print(f'  tail: {len(suspicious)} suspicious refs to local text')

    # tail 解析
    t = parse_tail(p['tail'], p['text_size'])
    fn_readable = t['filename_bytes'].decode('cp932', errors='replace')
    print(f'  tail: filename={fn_readable!r}, '
          f'{len(t["entry_offsets"])} entries')
    if t['entry_name_bytes']:
        names = [n.decode('cp932', errors='replace')
                 for n in t['entry_name_bytes'][:5]]
        print(f'    first 5 entries: '
              f'{list(zip(names, [hex(o) for o in t["entry_offsets"][:5]]))}')

    # tail rebuild round-trip
    rebuilt_tail = build_tail(t['type_tag'], t['entry_offsets'],
                              t['filename_bytes'], t['entry_name_bytes'])
    print(f'  tail round-trip: '
          f'{"OK" if rebuilt_tail == p["tail"] else "MISMATCH"}')

    rebuilt = build_te(p['header'], p['code'], p['text'], p['tail'])
    print(f'  full round-trip: {"OK" if rebuilt == data else "MISMATCH"}')
