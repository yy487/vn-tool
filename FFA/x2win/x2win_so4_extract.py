"""
X2WIN SO4 文本提取工具 (FFA/G-SYS engine, 天巫女姫)
  v1.0, developed by natsuko

用法:
  单文件:  python x2win_so4_extract.py A0_000.SO4
  单文件:  python x2win_so4_extract.py A0_000.SO4 -o output.json
  批量:    python x2win_so4_extract.py ./decoded_so4/ -o ./texts/

输出格式: GalTransl 兼容 JSON (id / name / message)

SO4 格式:
  线性 opcode 流: [u16 optype] [u16 oplen] [body...]
  文本容器 opcode:
    0x0488 (对话): body = [01 7F 00*4] [type(1B)] [param(5B)] [text\0]
                   type=0x01 → 对话文本, type=0x02 → 语音/CG指令(跳过)
    0x0015 (选项): body = [index(1B)] [param(5B)] [text\0]
  文本编码: cp932 (Shift-JIS)
  角色名分隔符: '/' (如 "翔太郎/「台词」", "/旁白文本")
"""

import os
import sys
import json
import struct
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# ============================================================
# SO4 opcode 解析
# ============================================================

def parse_opcodes(data: bytes) -> List[Tuple[int, int, int]]:
    """
    解析 SO4 opcode 流，返回 [(addr, optype, oplen), ...]

    容错处理: 某些 SO4 文件中存在 oplen=0 的 opcode (如 0x024F)，
    此时通过前向扫描找到下一个合法 opcode 边界来推断实际大小。
    """
    result = []
    cur = 0
    while cur + 4 <= len(data):
        optype, oplen = struct.unpack_from('<HH', data, cur)

        if oplen >= 4 and cur + oplen <= len(data):
            # 正常情况
            result.append((cur, optype, oplen))
            cur += oplen

        elif oplen < 4:
            # oplen 无效 — 前向扫描找下一个合法边界
            actual = _probe_next_boundary(data, cur)
            if actual > 0:
                result.append((cur, optype, actual))
                cur += actual
            else:
                cur += 4  # 最后手段: 跳过 4 字节

        else:
            break  # oplen 超出文件尾
    return result


def _probe_next_boundary(data: bytes, cur: int) -> int:
    """从 cur+4 开始扫描，找到下一个看起来合法的 opcode 起始位置，返回步长"""
    for skip in range(4, 256, 2):
        pos = cur + skip
        if pos + 4 > len(data):
            break
        t, l = struct.unpack_from('<HH', data, pos)
        if not (4 <= l <= 4000 and t < 0x2000):
            continue
        # 二次验证: 下一条也合法
        pos2 = pos + l
        if pos2 + 4 <= len(data):
            t2, l2 = struct.unpack_from('<HH', data, pos2)
            if 4 <= l2 <= 4000 and t2 < 0x2000:
                return skip
    return 0


# ============================================================
# 文本提取
# ============================================================

def extract_texts(data: bytes) -> List[Dict]:
    """
    从 SO4 文件中精确提取文本。
    基于 opcode 结构解析，不依赖盲扫。

    返回列表，每项包含:
      op_addr   - opcode 起始地址
      optype    - opcode 类型 (0x0488 或 0x0015)
      oplen     - opcode 总长度
      text_off  - 文本相对于文件起始的偏移
      text_size - 文本字节长度 (不含 \\0)
      name      - 角色名 (可为空)
      message   - 台词/旁白/选项文本
    """
    opcodes = parse_opcodes(data)
    entries = []

    for addr, optype, oplen in opcodes:
        body = data[addr + 4 : addr + oplen]

        if optype == 0x0488 and len(body) >= 13:
            # body[6] = 类型: 0x01=对话, 0x02=语音指令
            if body[6] != 0x01:
                continue
            text_start = 12  # body 内偏移
            text_raw = body[text_start:]
            null_pos = text_raw.find(b'\x00')
            if null_pos <= 0:
                continue
            try:
                text = text_raw[:null_pos].decode('cp932')
            except UnicodeDecodeError:
                continue

            name, message = _split_name(text)
            entries.append({
                'op_addr': addr,
                'optype': optype,
                'oplen': oplen,
                'text_off': addr + 4 + text_start,
                'text_size': null_pos,
                'name': name,
                'message': message,
            })

        elif optype == 0x0015 and len(body) >= 7:
            text_start = 6  # body 内偏移
            text_raw = body[text_start:]
            null_pos = text_raw.find(b'\x00')
            if null_pos <= 0:
                continue
            try:
                text = text_raw[:null_pos].decode('cp932')
            except UnicodeDecodeError:
                continue

            entries.append({
                'op_addr': addr,
                'optype': optype,
                'oplen': oplen,
                'text_off': addr + 4 + text_start,
                'text_size': null_pos,
                'name': '',
                'message': text,
            })

    return entries


def _split_name(text: str) -> Tuple[str, str]:
    """
    分离角色名和台词。
    格式: "角色名/「台词」" → (角色名, 「台词」)
           "/旁白文本"     → ('', 旁白文本)
    """
    if '/' not in text:
        return ('', text)

    idx = text.index('/')
    candidate = text[:idx]

    # '/' 在开头 → 旁白 (无角色名)
    if idx == 0:
        return ('', text[1:])

    # 角色名不应超过10个字符
    if len(candidate) <= 10:
        return (candidate, text[idx + 1:])

    # 太长 → 可能不是角色名分隔符
    return ('', text)


# ============================================================
# 单文件导出
# ============================================================

def export_file(so4_path: str, out_path: str) -> List[Dict]:
    """提取单个 SO4 文件的文本，输出 GalTransl JSON"""
    with open(so4_path, 'rb') as f:
        data = f.read()

    entries = extract_texts(data)

    if out_path:
        json_entries = []
        for i, e in enumerate(entries):
            json_entries.append({
                'id': i,
                'name': e['name'],
                'message': e['message'],
                'op_addr': f"0x{e['op_addr']:06X}",
                'text_off': f"0x{e['text_off']:06X}",
                'text_size': e['text_size'],
                'optype': f"0x{e['optype']:04X}",
                'oplen': e['oplen'],
            })
        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(json_entries, f, ensure_ascii=False, indent=2)

    return entries


# ============================================================
# 批量导出
# ============================================================

def batch_export(input_dir: str, output_dir: str):
    """批量提取文件夹中所有 SO4 文件"""
    os.makedirs(output_dir, exist_ok=True)
    inpath = Path(input_dir)

    globs = ['*.SO4', '*.so4', '*.SO4.dec', '*.so4.dec']
    files = sorted({f for g in globs for f in inpath.glob(g) if f.is_file()})
    if not files:
        print(f"未找到 SO4 文件: {input_dir}")
        return

    print(f"找到 {len(files)} 个 SO4 文件")
    print("-" * 50)

    ok = fail = total = 0
    for fp in files:
        stem = fp.name
        for sfx in ['.dec', '.SO4', '.so4']:
            if stem.endswith(sfx):
                stem = stem[:-len(sfx)]
        out = os.path.join(output_dir, stem + '.json')
        try:
            entries = export_file(str(fp), out)
            total += len(entries)
            ok += 1
            print(f"  {fp.name} → {len(entries)} 条")
        except Exception as e:
            fail += 1
            print(f"  {fp.name} 失败: {e}")

    print("-" * 50)
    print(f"完成: {ok} 成功 / {fail} 失败 / 共 {total} 条文本")


# ============================================================
# Main
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description='X2WIN SO4 文本提取工具 (天巫女姫)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python x2win_so4_extract.py x2_a0.SO4                 # → x2_a0.json
  python x2win_so4_extract.py x2_a0.SO4 -o out.json     # 指定输出
  python x2win_so4_extract.py ./decoded/ -o ./texts/     # 批量""")

    ap.add_argument('input', help='SO4 文件或文件夹')
    ap.add_argument('-o', '--output', default=None, help='输出 JSON 或文件夹')
    args = ap.parse_args()

    inp = Path(args.input)
    if inp.is_dir():
        outdir = args.output or str(inp) + '_text'
        batch_export(str(inp), outdir)
    elif inp.is_file():
        outpath = args.output or str(inp).rsplit('.', 1)[0] + '.json'
        entries = export_file(str(inp), outpath)
        print(f"提取 {len(entries)} 条文本 → {outpath}")
    else:
        print(f"路径不存在: {args.input}")
        sys.exit(1)


if __name__ == '__main__':
    main()
