"""
Z2WIN SO4 文本注入工具 (FFA/G-SYS engine)
  v1.1, developed by natsuko

用法:
  安全模式(等长替换):
    python so4_inject.py A0_000.json A0_000.SO4
    python so4_inject.py A0_000.json A0_000.SO4 -o patched.SO4

  变长模式(自动修正跳转表):
    python so4_inject.py A0_000.json A0_000.SO4 --varlen

  批量安全模式:
    python so4_inject.py ./texts/ ./decoded/ -o ./patched/

  批量变长模式:
    python so4_inject.py ./texts/ ./decoded/ -o ./patched/ --varlen

安全模式:  等长替换，过长截断+过短填充，不改变文件大小，零风险。
变长模式:  支持文本变长，自动扫描并修正 0x024F/0x021A/0x021B 跳转地址。
"""

import os
import sys
import json
import struct
import argparse
from pathlib import Path
from collections import namedtuple
from typing import List, Dict

# ============================================================
# SO4 opcode parser (for jump table)
# ============================================================

so4opindex_t = namedtuple("so4opindex_t", ['addr', 'optype', 'oplen'])

def parse_so4(data: bytes) -> List[so4opindex_t]:
    """解析 SO4 操作码流 (u16 opcode + u16 oplen)"""
    cur = 0
    result: List[so4opindex_t] = []
    while cur + 4 <= len(data):
        optype, oplen = struct.unpack_from("<HH", data, cur)
        if oplen == 0 or oplen < 4:
            cur += 4
            continue
        if cur + oplen > len(data):
            break
        result.append(so4opindex_t(cur, optype, oplen))
        cur += oplen
    return result

# ============================================================
# Jump table builder
# ============================================================

JUMP_OPCODES = (0x024F, 0x021A, 0x021B)
JUMP_PATTERNS = [
    (b'\x4F\x02', 4),  # 0x024F: target at +4
    (b'\x1A\x02', 4),  # 0x021A: target at +4
    (b'\x1B\x02', 4),  # 0x021B: target at +4
]

def build_jump_table(data: bytes) -> List[Dict]:
    """
    收集文件中所有跳转目标地址。
    同时扫描嵌套在 0x0093 容器内部的跳转指令。
    """
    seen = set()
    table = []

    def _add(target_pos, jumpto):
        if target_pos in seen:
            return
        seen.add(target_pos)
        table.append({
            'addr': target_pos, 'jumpto': jumpto,
            'addr_new': target_pos, 'jumpto_new': jumpto,
        })

    # 扫描跳转 pattern
    for pat, off in JUMP_PATTERNS:
        pos = 0
        while True:
            pos = data.find(pat, pos)
            if pos < 0:
                break
            if pos + 8 <= len(data):
                oplen = struct.unpack_from('<H', data, pos + 2)[0]
                if 8 <= oplen < 0x200:
                    target_pos = pos + off
                    jumpto = struct.unpack_from('<I', data, target_pos)[0]
                    if 0 < jumpto < len(data):
                        _add(target_pos, jumpto)
            pos += 2

    return table

# ============================================================
# 安全注入 (等长替换)
# ============================================================

def inject_safe(entries: List[Dict], data: bytearray,
                encoding: str = 'cp932',
                pad_byte: int = 0x20) -> bytearray:
    """
    等长替换模式：文本过长截断，过短用空格填充。
    不改变文件大小，不需要跳转修正。
    未修改的文本条目保持原始字节不变。
    """
    patched = skipped = truncated = unchanged = 0

    for entry in entries:
        addr = _parse_addr(entry.get('addr'))
        if addr is None:
            continue
        org_size = entry.get('size', 0)
        text = _get_full_text(entry)
        if not text or org_size <= 0:
            continue
        if addr + org_size > len(data):
            skipped += 1
            continue

        # 对比原始字节：如果文本未修改则跳过，避免编码转换破坏原始数据
        org_bytes = bytes(data[addr:addr + org_size])
        try:
            org_text = org_bytes.rstrip(b'\x00').rstrip(bytes([pad_byte])).decode('cp932')
        except UnicodeDecodeError:
            org_text = None
        if org_text is not None and org_text == text.rstrip():
            unchanged += 1
            continue

        try:
            enc = text.encode(encoding)
        except UnicodeEncodeError:
            print(f"  编码失败 0x{addr:06X}, 跳过")
            skipped += 1
            continue

        if len(enc) > org_size:
            enc = _truncate_sjis(enc, org_size, encoding)
            truncated += 1

        # 填充到原始长度
        if len(enc) < org_size:
            enc = enc + bytes([pad_byte]) * (org_size - len(enc))

        data[addr:addr + org_size] = enc
        patched += 1

    print(f"  修改 {patched} 条, 未变 {unchanged} 条, 跳过 {skipped} 条", end="")
    if truncated:
        print(f", 截断 {truncated} 条", end="")
    print()
    return data


def _truncate_sjis(enc: bytes, maxlen: int, encoding: str) -> bytes:
    """截断到 maxlen 字节，确保不切断 SJIS 双字节字符"""
    t = enc[:maxlen]
    while len(t) > 0:
        try:
            t.decode(encoding)
            return t
        except UnicodeDecodeError:
            t = t[:-1]
    return b''

# ============================================================
# 变长注入 (自动修正跳转)
# ============================================================

def inject_varlen(entries: List[Dict], data: bytearray,
                  encoding: str = 'cp932') -> bytearray:
    """
    变长替换模式：文本可以比原文长或短。
    自动扫描和修正所有跳转目标地址。
    """
    jumptable = build_jump_table(bytes(data))

    # 收集并按地址降序排列 (从后往前 patch 避免偏移累积)
    patches = []
    unchanged = 0
    for entry in entries:
        addr = _parse_addr(entry.get('addr'))
        if addr is None:
            continue
        org_size = entry.get('size', 0)
        text = _get_full_text(entry)
        if not text or org_size <= 0:
            continue

        # 跳过未修改的条目
        if addr + org_size <= len(data):
            org_bytes = bytes(data[addr:addr + org_size])
            try:
                org_text = org_bytes.rstrip(b'\x00').rstrip(b'\x20').decode('cp932')
                if org_text == text.rstrip():
                    unchanged += 1
                    continue
            except UnicodeDecodeError:
                pass

        try:
            enc = text.encode(encoding)
        except UnicodeEncodeError:
            print(f"  编码失败 0x{addr:06X}, 跳过")
            continue
        patches.append((addr, org_size, enc))

    patches.sort(key=lambda x: x[0], reverse=True)

    for addr, org_size, new_bytes in patches:
        if addr + org_size > len(data):
            continue

        delta = len(new_bytes) - org_size
        old_end = addr + org_size

        # 替换数据
        data[addr:old_end] = new_bytes
        # data 长度已改变 delta 字节

        if delta != 0:
            # 修正跳转表
            for jmp in jumptable:
                if jmp['addr_new'] > addr:
                    jmp['addr_new'] += delta
                if jmp['jumpto_new'] > addr:
                    jmp['jumpto_new'] += delta

    # 写回修正后的跳转地址
    changed = 0
    for jmp in jumptable:
        if jmp['jumpto_new'] != jmp['jumpto']:
            a = jmp['addr_new']
            if 0 <= a and a + 4 <= len(data):
                struct.pack_into('<I', data, a, jmp['jumpto_new'])
                changed += 1

    if changed:
        print(f"  修正了 {changed} 个跳转地址")
    return data

# ============================================================
# 辅助函数
# ============================================================

def _parse_addr(val) -> int:
    """解析地址字段 (支持 int / "0x1234" / "1234")"""
    if val is None:
        return None
    if isinstance(val, int):
        return val
    try:
        return int(val, 0)
    except (ValueError, TypeError):
        return None


def _get_full_text(entry: Dict) -> str:
    """从 JSON 条目还原完整文本（拼合 name + message）"""
    name = entry.get('name', '')
    message = entry.get('message', '')
    if name:
        return f'{name}_{message}'  # 还原为 "角色名_「台词」"
    return message

# ============================================================
# 单文件注入
# ============================================================

def inject_file(jsonpath: str, orgpath: str, outpath: str,
                encoding: str = 'cp932', varlen: bool = False):
    """注入翻译文本到单个 SO4 文件"""
    with open(jsonpath, 'r', encoding='utf-8') as fp:
        entries = json.load(fp)
    with open(orgpath, 'rb') as fp:
        data = bytearray(fp.read())

    if varlen:
        data = inject_varlen(entries, data, encoding)
    else:
        data = inject_safe(entries, data, encoding)

    with open(outpath, 'wb') as fp:
        fp.write(data)

# ============================================================
# 批量注入
# ============================================================

SO4_SUFFIXES = ['.SO4.dec', '.SO4', '.so4.dec', '.so4']

def batch_inject(trans_dir: str, orig_dir: str, output_dir: str,
                 encoding: str = 'cp932', varlen: bool = False):
    """批量注入：将 trans_dir 中的 JSON 翻译写回 orig_dir 中对应的 SO4"""
    os.makedirs(output_dir, exist_ok=True)
    tpath = Path(trans_dir)
    opath = Path(orig_dir)

    jsons = sorted(tpath.glob('*.json'))
    if not jsons:
        print(f"未找到 JSON 文件: {trans_dir}")
        return

    print(f"找到 {len(jsons)} 个翻译文件")
    mode_str = "变长" if varlen else "安全(等长)"
    print(f"模式: {mode_str}")
    print("-" * 50)

    ok = fail = 0
    for jf in jsons:
        stem = jf.stem
        # 查找匹配的原始 SO4
        org = None
        for sfx in SO4_SUFFIXES:
            candidate = opath / (stem + sfx)
            if candidate.exists():
                org = candidate
                break
        if org is None:
            print(f"  {jf.name}: 找不到原始 SO4 ({stem}.*), 跳过")
            fail += 1
            continue

        outfile = os.path.join(output_dir, org.name)
        try:
            print(f"  {jf.name} + {org.name} → {Path(outfile).name}")
            inject_file(str(jf), str(org), outfile, encoding, varlen)
            ok += 1
        except Exception as e:
            fail += 1
            print(f"    失败: {e}")

    print("-" * 50)
    print(f"完成: {ok} 成功 / {fail} 失败")

# ============================================================
# Main
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description='Z2WIN SO4 文本注入工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  # 安全模式 (等长替换，推荐初次使用)
  python so4_inject.py A0_000.json A0_000.SO4
  python so4_inject.py A0_000.json A0_000.SO4 -o patched.SO4

  # 变长模式 (自动修正跳转表)
  python so4_inject.py A0_000.json A0_000.SO4 --varlen

  # 批量安全模式
  python so4_inject.py ./texts/ ./decoded/ -o ./patched/

  # 批量变长模式
  python so4_inject.py ./texts/ ./decoded/ -o ./patched/ --varlen""")

    ap.add_argument('input', help='翻译 JSON 文件或 JSON 文件夹')
    ap.add_argument('original', help='原始 SO4 文件或 SO4 文件夹')
    ap.add_argument('-o', '--output', default=None,
                    help='输出文件或文件夹 (默认: 原始文件名.patched)')
    ap.add_argument('--encoding', default='cp932', help='目标编码 (默认 cp932)')
    ap.add_argument('--varlen', action='store_true',
                    help='变长替换模式 (默认: 等长安全模式)')
    args = ap.parse_args()

    inp = Path(args.input)
    org = Path(args.original)

    if inp.is_dir() and org.is_dir():
        # 批量模式
        outdir = args.output or str(org) + '_patched'
        batch_inject(str(inp), str(org), outdir, args.encoding, args.varlen)

    elif inp.is_file() and org.is_file():
        # 单文件模式
        outpath = args.output or (str(org) + '.patched')
        inject_file(str(inp), str(org), outpath, args.encoding, args.varlen)
        print(f"注入完成 → {outpath}")

    else:
        print("错误: input 和 original 必须同为文件或同为文件夹")
        sys.exit(1)


if __name__ == '__main__':
    main()
