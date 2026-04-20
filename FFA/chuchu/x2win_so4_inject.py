"""
X2WIN SO4 文本注入工具 (FFA/G-SYS engine, 天巫女姫)
  v1.0, developed by natsuko

用法:
  等长模式(安全):
    python x2win_so4_inject.py trans.json orig.SO4
    python x2win_so4_inject.py trans.json orig.SO4 -o patched.SO4

  变长模式(修正oplen+跳转):
    python x2win_so4_inject.py trans.json orig.SO4 --varlen

  批量:
    python x2win_so4_inject.py ./texts/ ./decoded/ -o ./patched/
    python x2win_so4_inject.py ./texts/ ./decoded/ -o ./patched/ --varlen

等长模式: 过长截断+过短填充，不改变文件大小，零风险。
变长模式: 文本可变长，自动修正容器 oplen 和跳转地址。

变长注入三步修正:
  1. 替换文本字节 → 文件大小变化 delta
  2. 修正所属容器 (0x0488/0x0015) 的 oplen 字段
  3. 修正所有跳转 opcode (0x024F/0x021A/0x021B) 中指向变化区域之后的地址
"""

import os
import sys
import json
import struct
import argparse
from pathlib import Path
from typing import List, Dict, Tuple

# ============================================================
# 跳转地址引用表
# ============================================================

# 确认的地址引用: optype → body 内偏移列表
# 0x024F, 0x021A, 0x021B: body+0 处有 u32 跳转目标 (100% 命中)
JUMP_OPS = {
    0x024F: [0],
    0x021A: [0],
    0x021B: [0],
}


def collect_jump_refs(data: bytes) -> List[Dict]:
    """
    收集文件中所有跳转地址引用。
    返回 [{file_off, old_target}, ...] (file_off 是 u32 值在文件中的绝对偏移)

    容错: 处理 oplen=0 的 opcode，通过前向扫描推断实际大小。
    """
    refs = []
    cur = 0
    while cur + 4 <= len(data):
        optype, oplen = struct.unpack_from('<HH', data, cur)

        if oplen < 4:
            # oplen 无效 — 前向扫描
            actual = _probe_next_boundary(data, cur)
            if actual > 0:
                oplen = actual
            else:
                cur += 4
                continue

        if cur + oplen > len(data):
            break

        if optype in JUMP_OPS:
            for body_off in JUMP_OPS[optype]:
                file_off = cur + 4 + body_off
                if file_off + 4 <= cur + oplen:
                    target = struct.unpack_from('<I', data, file_off)[0]
                    refs.append({'file_off': file_off, 'old_target': target})
        cur += oplen
    return refs


def _probe_next_boundary(data: bytes, cur: int) -> int:
    """从 cur+4 开始扫描，找到下一个合法 opcode 起始位置，返回步长"""
    for skip in range(4, 256, 2):
        pos = cur + skip
        if pos + 4 > len(data):
            break
        t, l = struct.unpack_from('<HH', data, pos)
        if not (4 <= l <= 4000 and t < 0x2000):
            continue
        pos2 = pos + l
        if pos2 + 4 <= len(data):
            t2, l2 = struct.unpack_from('<HH', data, pos2)
            if 4 <= l2 <= 4000 and t2 < 0x2000:
                return skip
    return 0


# ============================================================
# 等长注入
# ============================================================

def inject_safe(entries: List[Dict], data: bytearray,
                encoding: str = 'cp932') -> bytearray:
    """等长替换: 过长截断，过短 0x00 填充"""
    patched = skipped = truncated = unchanged = 0

    for entry in entries:
        text_off = _parse_int(entry.get('text_off'))
        text_size = entry.get('text_size', 0)
        if text_off is None or text_size <= 0:
            skipped += 1
            continue
        if text_off + text_size > len(data):
            skipped += 1
            continue

        full_text = _rebuild_text(entry)

        # 跳过未修改的条目
        org_raw = bytes(data[text_off:text_off + text_size])
        try:
            org_text = org_raw.decode('cp932')
            if org_text == full_text:
                unchanged += 1
                continue
        except UnicodeDecodeError:
            pass

        try:
            enc = full_text.encode(encoding)
        except UnicodeEncodeError:
            print(f"  编码失败 0x{text_off:06X}, 跳过")
            skipped += 1
            continue

        if len(enc) > text_size:
            enc = _truncate_dbcs(enc, text_size, encoding)
            truncated += 1

        # 填充到原始大小 (用 0x00)
        if len(enc) < text_size:
            enc = enc + b'\x00' * (text_size - len(enc))

        data[text_off:text_off + text_size] = enc
        patched += 1

    print(f"  修改 {patched}, 未变 {unchanged}, 跳过 {skipped}", end="")
    if truncated:
        print(f", 截断 {truncated}", end="")
    print()
    return data


# ============================================================
# 变长注入
# ============================================================

def inject_varlen(entries: List[Dict], data: bytearray,
                  encoding: str = 'cp932') -> bytearray:
    """
    变长替换: 文本可长可短。
    修正三项: 文本字节 + 容器 oplen + 跳转地址。
    """
    # 1. 收集跳转引用
    jump_refs = collect_jump_refs(bytes(data))

    # 2. 收集需要修改的条目 (按地址降序，从后往前改避免偏移漂移)
    patches = []
    unchanged = 0
    for entry in entries:
        text_off = _parse_int(entry.get('text_off'))
        text_size = entry.get('text_size', 0)
        op_addr = _parse_int(entry.get('op_addr'))
        oplen_orig = entry.get('oplen', 0)
        if text_off is None or text_size <= 0 or op_addr is None:
            continue

        full_text = _rebuild_text(entry)

        # 跳过未修改
        if text_off + text_size <= len(data):
            org_raw = bytes(data[text_off:text_off + text_size])
            try:
                if org_raw.decode('cp932') == full_text:
                    unchanged += 1
                    continue
            except UnicodeDecodeError:
                pass

        try:
            enc = full_text.encode(encoding)
        except UnicodeEncodeError:
            print(f"  编码失败 0x{text_off:06X}, 跳过")
            continue

        patches.append({
            'text_off': text_off,
            'text_size': text_size,
            'new_bytes': enc,
            'op_addr': op_addr,
            'oplen_orig': oplen_orig,
        })

    patches.sort(key=lambda x: x['text_off'], reverse=True)

    # 3. 从后往前逐个应用
    patched_count = 0
    for p in patches:
        text_off = p['text_off']
        old_size = p['text_size']
        new_bytes = p['new_bytes']
        op_addr = p['op_addr']
        delta = len(new_bytes) - old_size

        # 替换文本字节 (+1 for null terminator: 保留原 \0 or 追加)
        old_end = text_off + old_size
        data[text_off:old_end] = new_bytes

        if delta != 0:
            # 修正容器 oplen
            _fix_oplen(data, op_addr, delta)

            # 修正跳转地址
            for ref in jump_refs:
                # ref['file_off'] 指向 u32 值在文件中的位置
                # 如果这个位置在修改点之后，需要调整位置
                if ref['file_off'] > text_off:
                    ref['file_off'] += delta
                # 如果跳转目标在修改点之后，需要调整目标
                if ref['old_target'] > text_off:
                    ref['old_target'] += delta

        patched_count += 1

    # 4. 写回所有跳转地址
    jump_fixed = 0
    for ref in jump_refs:
        off = ref['file_off']
        target = ref['old_target']
        if 0 <= off and off + 4 <= len(data):
            old_val = struct.unpack_from('<I', data, off)[0]
            if old_val != target:
                struct.pack_into('<I', data, off, target)
                jump_fixed += 1

    print(f"  修改 {patched_count}, 未变 {unchanged}", end="")
    if jump_fixed:
        print(f", 修正 {jump_fixed} 个跳转", end="")
    print()
    return data


def _fix_oplen(data: bytearray, op_addr: int, delta: int):
    """修正 opcode 的 oplen 字段 (op_addr+2 处的 u16)"""
    if op_addr + 4 > len(data):
        return
    old_oplen = struct.unpack_from('<H', data, op_addr + 2)[0]
    new_oplen = old_oplen + delta
    if new_oplen < 4:
        print(f"  警告: oplen 修正后 < 4 @0x{op_addr:06X}, 跳过")
        return
    if new_oplen > 0xFFFF:
        print(f"  警告: oplen 溢出 @0x{op_addr:06X}, 跳过")
        return
    struct.pack_into('<H', data, op_addr + 2, new_oplen)


# ============================================================
# 辅助函数
# ============================================================

def _parse_int(val) -> int:
    """解析地址 (支持 int / "0x1234" / "1234")"""
    if val is None:
        return None
    if isinstance(val, int):
        return val
    try:
        return int(val, 0)
    except (ValueError, TypeError):
        return None


def _rebuild_text(entry: Dict) -> str:
    """从 JSON 条目还原完整文本 (name/message 拼合)"""
    name = entry.get('name', '')
    message = entry.get('message', '')
    if name:
        return f'{name}/{message}'
    elif message and not message.startswith('/'):
        # 检查原文是否以'/'开头(旁白)
        # 如果 optype 是 0x0488 且无角色名，可能是旁白
        optype = _parse_int(entry.get('optype', 0))
        if optype == 0x0488:
            return f'/{message}'
    return message


def _truncate_dbcs(enc: bytes, maxlen: int, encoding: str) -> bytes:
    """截断到 maxlen 字节，不切断双字节字符"""
    t = enc[:maxlen]
    while len(t) > 0:
        try:
            t.decode(encoding)
            return t
        except UnicodeDecodeError:
            t = t[:-1]
    return b''


# ============================================================
# 单文件注入
# ============================================================

def inject_file(json_path: str, org_path: str, out_path: str,
                encoding: str = 'cp932', varlen: bool = False):
    """注入翻译到单个 SO4"""
    with open(json_path, 'r', encoding='utf-8') as f:
        entries = json.load(f)
    with open(org_path, 'rb') as f:
        data = bytearray(f.read())

    if varlen:
        data = inject_varlen(entries, data, encoding)
    else:
        data = inject_safe(entries, data, encoding)

    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(data)


# ============================================================
# 批量注入
# ============================================================

def batch_inject(trans_dir: str, orig_dir: str, output_dir: str,
                 encoding: str = 'cp932', varlen: bool = False):
    """批量注入"""
    os.makedirs(output_dir, exist_ok=True)
    tpath = Path(trans_dir)
    opath = Path(orig_dir)

    jsons = sorted(tpath.glob('*.json'))
    if not jsons:
        print(f"未找到 JSON: {trans_dir}")
        return

    mode = "变长" if varlen else "等长(安全)"
    print(f"找到 {len(jsons)} 个翻译文件, 模式: {mode}")
    print("-" * 50)

    ok = fail = 0
    suffixes = ['.SO4.dec', '.SO4', '.so4.dec', '.so4']
    for jf in jsons:
        stem = jf.stem
        org = None
        for sfx in suffixes:
            c = opath / (stem + sfx)
            if c.exists():
                org = c
                break
        if org is None:
            print(f"  {jf.name}: 找不到原始 SO4, 跳过")
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
        description='X2WIN SO4 文本注入工具 (天巫女姫)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python x2win_so4_inject.py trans.json orig.SO4             # 等长安全模式
  python x2win_so4_inject.py trans.json orig.SO4 --varlen    # 变长模式
  python x2win_so4_inject.py ./texts/ ./decoded/ -o ./out/   # 批量""")

    ap.add_argument('input', help='翻译 JSON 或 JSON 文件夹')
    ap.add_argument('original', help='原始 SO4 或 SO4 文件夹')
    ap.add_argument('-o', '--output', default=None, help='输出文件/夹')
    ap.add_argument('--encoding', default='cp932', help='目标编码 (默认 cp932)')
    ap.add_argument('--varlen', action='store_true', help='变长替换模式')
    args = ap.parse_args()

    inp = Path(args.input)
    org = Path(args.original)

    if inp.is_dir() and org.is_dir():
        outdir = args.output or str(org) + '_patched'
        batch_inject(str(inp), str(org), outdir, args.encoding, args.varlen)
    elif inp.is_file() and org.is_file():
        outpath = args.output or (str(org) + '.patched')
        inject_file(str(inp), str(org), outpath, args.encoding, args.varlen)
        print(f"注入完成 → {outpath}")
    else:
        print("错误: input 和 original 必须同为文件或同为文件夹")
        sys.exit(1)


if __name__ == '__main__':
    main()
