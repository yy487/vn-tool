"""
Z2WIN SO4 文本提取工具 (FFA/G-SYS engine)
  v1.1, developed by natsuko

用法:
  单文件:  python so4_extract.py A0_000.SO4
  单文件:  python so4_extract.py A0_000.SO4 -o output.json
  批量:    python so4_extract.py ./decoded_so4/ -o ./texts/
  全量:    python so4_extract.py A0_000.SO4 --all   (含系统路径/变量引用)

输出格式: GalTransl 兼容 JSON (id / name / message / addr / size)
"""

import os
import sys
import json
import struct
import argparse
from pathlib import Path
from typing import List, Dict

# ============================================================
# SJIS string scanner
# ============================================================

def scan_sjis_strings(data: bytes, min_chars: int = 3) -> List[Dict]:
    """扫描二进制数据中所有 null 结尾的 Shift-JIS 字符串"""
    results = []
    i = 0
    while i < len(data) - 2:
        b = data[i]
        if not (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xFC or 0x21 <= b <= 0x7E):
            i += 1
            continue

        start = i
        chars = 0
        jp_chars = 0         # SJIS 双字节字符数
        ascii_chars = 0      # 独立 ASCII 字符数
        j = i
        while j < len(data) and data[j] != 0:
            pb = data[j]
            if (0x81 <= pb <= 0x9F or 0xE0 <= pb <= 0xFC) and j + 1 < len(data):
                trail = data[j + 1]
                if 0x40 <= trail <= 0xFC and trail != 0x7F:
                    j += 2; chars += 1; jp_chars += 1
                else:
                    break
            elif 0x20 <= pb <= 0x7E:
                j += 1; chars += 1; ascii_chars += 1
            elif pb == 0x0A:
                j += 1
            else:
                break

        if chars >= min_chars and j < len(data) and data[j] == 0 and jp_chars > 0:
            try:
                text = data[start:j].decode('cp932')
                if _is_valid_text(text, jp_chars, ascii_chars):
                    results.append({'addr': start, 'size': j - start, 'text': text})
                i = j + 1
                continue
            except (UnicodeDecodeError, ValueError):
                pass
        i += 1
    return results


def _is_valid_text(text: str, jp_chars: int, ascii_chars: int) -> bool:
    """
    启发式过滤：排除二进制数据被误读为 SJIS 的假字符串。
    
    误读特征:
    - 极短 (1-2个字符) 且不含常用日文标点/助词
    - SJIS lead byte + 恰好落在合法 trail byte 范围的数据字节
    """
    t = text.strip()
    if not t:
        return False

    # 黑名单：已知的 FFA 引擎操作码参数误读为 SJIS 的固定组合
    # 这些是 SO4 字节码中反复出现的参数序列，恰好构成合法 SJIS
    _BINARY_BLACKLIST = {'祷劍'}
    if t in _BINARY_BLACKLIST:
        return False

    # 纯全角空格/标点 → 有效 (常见于对白缩进)
    if all(c in '　 ' for c in t):
        return len(t) >= 4  # 太短的空白串排除

    # 长文本基本不会是误读
    if len(t) >= 6:
        return True

    # 中等长度 (3-5字符): 检查是否含常见日文要素
    if len(t) >= 3:
        # 含助词/标点/假名 → 大概率有效
        JP_INDICATORS = set(
            'のはがをにでもとへやかなねよわ'  # 助词
            'ぁあぃいぅうぇえぉおかきくけこさしすせそたちつてとなにぬねの'
            'はひふへほまみむめもやゆよらりるれろわをん'  # 平假名
            'ァアィイゥウェエォオカキクケコサシスセソタチツテトナニヌネノ'
            'ハヒフヘホマミムメモヤユヨラリルレロワヲン'  # 片假名
            '、。！？…─―「」『』（）〈〉《》【】'  # 标点
        )
        if any(c in JP_INDICATORS for c in t):
            return True
        # 纯 ASCII 部分合理 (如 "ＯＫ", "ＣＤ") → 有效
        if ascii_chars == 0:
            # 3-5个纯汉字无助词 → 可能有效 (如 "陰舞の舞台"去掉の后仍有)
            # 但2个纯汉字 → 高概率误读
            return len(t) >= 3
        return True

    # 极短文本 (1-2字符)
    if len(t) <= 2:
        # 排除误读模式1：SJIS 汉字 + 低位 ASCII (如 歔` 術p 揺h)
        raw = t.encode('cp932', errors='replace')
        has_standalone_ascii = False
        k = 0
        while k < len(raw):
            b = raw[k]
            if (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xFC) and k + 1 < len(raw):
                k += 2
            else:
                if 0x20 <= b <= 0x7E:
                    has_standalone_ascii = True
                k += 1
        if has_standalone_ascii:
            return False  # 短文本混入独立 ASCII → 大概率误读

        # 排除误读模式2：二进制操作码参数恰好凑成 SJIS 冷僻字组合
        # 特征：两个字都是 JIS 第二水准以后的冷僻字（Unicode CJK 中不常用区域）
        # 常见日文汉字在 Unicode 0x4E00-0x9FFF，冷僻字在更高区或生僻编码
        rare_count = 0
        for ch in t:
            cp = ord(ch)
            # 冷僻判定：不在常用汉字/假名/符号/全角英数范围
            is_common = (
                0x3040 <= cp <= 0x30FF  # 假名
                or 0x4E00 <= cp <= 0x9FAF  # CJK 统一汉字基本区
                or 0x3000 <= cp <= 0x303F  # CJK 标点
                or 0xFF00 <= cp <= 0xFFEF  # 全角英数
            )
            if not is_common:
                rare_count += 1
        if rare_count >= 2:
            return False  # 两个字都是冷僻字 → 大概率误读

        # 纯 SJIS 双字节短词 (如 変更、木村、博之) → 保留
        return True

    return True

# ============================================================
# Text classification
# ============================================================

SYSTEM_PATTERNS = [
    '.DAT', '.LST', '.TAG', '.REG', '.DEF', '.SCP',
    '.avi', '.MID', '.PT1', '.wav', '.bmp',
    '\\', '/', 'SOFTWARE', 'Microsoft', 'Windows',
    'ActiveMovie', 'Indeo', 'AVI',
]
VARREF_PATTERNS = ['$d', '$s', '$p', '$D']
SLOT_PATTERNS = ['$d45$d', '$s1']


def classify_text(text: str) -> str:
    """
    分类文本:
      system  — 文件路径/注册表/技术标识
      format  — 变量引用格式串 ($d / $s)
      ui      — 可翻译的 UI/对白文本
      empty   — 空白填充
    """
    t = text.strip()
    if not t or all(c in '　 ' for c in t):
        return 'empty'
    if any(p in t for p in SYSTEM_PATTERNS):
        return 'system'
    if any(p in t for p in SLOT_PATTERNS):
        return 'format'
    cleaned = t.replace('$D10', '').replace('$D0A', '')
    if any(p in cleaned for p in VARREF_PATTERNS):
        return 'format'
    if all(ord(c) < 0x80 for c in t):
        return 'system'
    return 'ui'

# ============================================================
# 单文件提取
# ============================================================

def export_so4(so4path: str, outpath: str,
               encoding: str = 'cp932',
               include_all: bool = False) -> List[Dict]:
    """
    提取一个 SO4 文件中的文本，输出 GalTransl JSON。
    返回提取到的文本条目列表。
    """
    with open(so4path, 'rb') as fp:
        data = fp.read()

    all_strings = scan_sjis_strings(data, min_chars=2)

    texts = []
    seen = set()
    for item in all_strings:
        if item['addr'] in seen:
            continue
        cat = classify_text(item['text'])
        if cat == 'empty':
            continue
        if not include_all and cat in ('system', 'format'):
            continue
        texts.append({
            'addr': item['addr'],
            'size': item['size'],
            'text': item['text'],
            'category': cat,
        })
        seen.add(item['addr'])

    # 写 JSON
    if outpath:
        entries = []
        for i, t in enumerate(texts):
            name = ''
            message = t['text']

            # 分离角色名: 格式 "角色名_「台词」" 或 "角色名_『台词』"
            # 下划线 _ 后紧跟 「 或 『 是角色对白的固定格式
            for bracket in ('_「', '_『'):
                if bracket in message:
                    sep_idx = message.index(bracket)
                    candidate_name = message[:sep_idx]
                    if len(candidate_name) <= 10 and not candidate_name.startswith('　'):
                        name = candidate_name
                        message = message[sep_idx + 1:]  # 保留「台词」或『台词』
                    break

            entries.append({
                'id': i,
                'name': name,
                'message': message,
                'addr': f"0x{t['addr']:06X}",
                'size': t['size'],
                'category': t['category'],
            })
        with open(outpath, 'w', encoding='utf-8') as fp:
            json.dump(entries, fp, ensure_ascii=False, indent=2)

    return texts

# ============================================================
# 批量提取
# ============================================================

SO4_GLOBS = ['*.SO4', '*.SO4.dec', '*.so4', '*.so4.dec']

def batch_export(input_dir: str, output_dir: str,
                 encoding: str = 'cp932',
                 include_all: bool = False):
    """批量提取文件夹中所有 SO4 文件的文本"""
    os.makedirs(output_dir, exist_ok=True)
    inpath = Path(input_dir)

    files = sorted({f for g in SO4_GLOBS for f in inpath.glob(g) if f.is_file()})
    if not files:
        print(f"未找到 SO4 文件: {input_dir}")
        return

    print(f"找到 {len(files)} 个 SO4 文件")
    print("-" * 50)

    ok = fail = total = 0
    for fp in files:
        stem = fp.name
        for suffix in ['.dec', '.SO4', '.so4']:
            stem = stem.replace(suffix, '') if stem.endswith(suffix) else stem
        outfile = os.path.join(output_dir, stem + '.json')
        try:
            texts = export_so4(str(fp), outfile, encoding, include_all)
            total += len(texts)
            ok += 1
            print(f"  {fp.name} → {len(texts)} 条")
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
        description='Z2WIN SO4 文本提取工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python so4_extract.py A0_000.SO4                  # 单文件 → A0_000.json
  python so4_extract.py A0_000.SO4 -o out.json      # 指定输出
  python so4_extract.py ./decoded/ -o ./texts/       # 批量
  python so4_extract.py A0_000.SO4 --all             # 含系统字符串""")

    ap.add_argument('input', help='SO4 文件或包含 SO4 的文件夹')
    ap.add_argument('-o', '--output', default=None,
                    help='输出 JSON 文件或文件夹 (默认: 同名 .json / out/)')
    ap.add_argument('--encoding', default='cp932', help='文本编码 (默认 cp932)')
    ap.add_argument('--all', action='store_true', help='导出全部字符串(含系统路径)')
    args = ap.parse_args()

    inp = Path(args.input)

    if inp.is_dir():
        # 批量模式
        outdir = args.output or str(inp) + '_text'
        batch_export(str(inp), outdir, args.encoding, args.all)
    elif inp.is_file():
        # 单文件模式
        if args.output and Path(args.output).suffix == '':
            # output looks like a directory
            os.makedirs(args.output, exist_ok=True)
            stem = inp.stem.replace('.SO4', '').replace('.so4', '')
            outpath = os.path.join(args.output, stem + '.json')
        else:
            outpath = args.output or str(inp).rsplit('.', 1)[0] + '.json'
        texts = export_so4(str(inp), outpath, args.encoding, args.all)
        print(f"提取 {len(texts)} 条文本 → {outpath}")
    else:
        print(f"路径不存在: {args.input}")
        sys.exit(1)


if __name__ == '__main__':
    main()
