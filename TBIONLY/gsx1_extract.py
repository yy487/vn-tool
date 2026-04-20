# -*- coding: utf-8 -*-
"""
GSX1 (.fbx) 文本提取器 — ペンギンワークス Love Caba 引擎

输出:
  <n>.json        GalTransl 格式(去重,仅含日文条目)
  <n>.raw.json    完整 dump(含 ASCII 函数名,调试用,保留所有出现位置)
  <n>.stats.txt   统计报告
"""
import struct, json, os, sys, re
from collections import Counter

MAGIC = 0x31585347  # "GSX1"
JP_RE = re.compile(r'[\u3040-\u30ff\u4e00-\u9fff\uff00-\uffef]')


def parse_header(data):
    mg, ver, str_off, str_sz, ta_off, ta_raw, tb_off, tb_raw, tc_off, tc_raw = \
        struct.unpack_from('<10I', data, 0)
    if mg != MAGIC:
        raise ValueError(f'bad magic {mg:#x}')
    return dict(
        version  = ver,
        str_off  = str_off,  str_size = str_sz,
        ta_off   = ta_off,   ta_count = ta_raw >> 4,
        tb_off   = tb_off,   tb_count = tb_raw >> 3,
        tc_off   = tc_off,   tc_count = tc_raw >> 3,
    )


def extract(path, out_dir):
    with open(path, 'rb') as f:
        data = f.read()
    h = parse_header(data)
    name = os.path.splitext(os.path.basename(path))[0]

    str_base = h['str_off']
    pool = data[str_base:str_base + h['str_size']]
    starts = {0}
    for i, b in enumerate(pool):
        if b == 0 and i + 1 < len(pool):
            starts.add(i + 1)

    def read_str_at(str_off):
        if str_off == -1:
            return None, 'NULL'
        if str_off < 0 or str_off >= h['str_size']:
            return None, f'OOB({str_off:#x})'
        if str_off not in starts:
            return None, f'UNALIGNED({str_off:#x})'
        abs_pos = str_base + str_off
        end = data.index(b'\x00', abs_pos)
        try:
            return data[abs_pos:end].decode('cp932'), None
        except UnicodeDecodeError as e:
            return None, f'DECODE({e})'

    # 扫 TABLE_C
    tc_base = h['tc_off']
    tc_refs = []
    errors = []
    for i in range(h['tc_count']):
        off = tc_base + i * 8
        if data[off] & 1 == 0:
            continue
        opcode = struct.unpack_from('<I', data, off)[0]
        str_off = struct.unpack_from('<i', data, off + 4)[0]
        text, err = read_str_at(str_off)
        if err:
            errors.append((i, opcode, str_off, err))
            continue
        tc_refs.append(dict(
            src='TC', tc_index=i, tc_byte_off=off - tc_base,
            opcode=opcode, str_off=str_off, text=text,
            has_jp=bool(JP_RE.search(text)),
        ))

    # 扫 TABLE_A
    ta_base = h['ta_off']
    ta_refs = []
    for i in range(h['ta_count']):
        off = ta_base + i * 16
        str_off = struct.unpack_from('<i', data, off + 4)[0]
        code_off = struct.unpack_from('<I', data, off + 12)[0]
        text, err = read_str_at(str_off)
        if err:
            continue
        ta_refs.append(dict(
            src='TA', ta_index=i, str_off=str_off, code_off=code_off,
            text=text, has_jp=bool(JP_RE.search(text)),
        ))

    os.makedirs(out_dir, exist_ok=True)
    raw_path   = os.path.join(out_dir, f'{name}.raw.json')
    gt_path    = os.path.join(out_dir, f'{name}.json')
    stats_path = os.path.join(out_dir, f'{name}.stats.txt')

    with open(raw_path, 'w', encoding='utf-8') as f:
        json.dump({'header': h, 'table_c_refs': tc_refs, 'table_a_refs': ta_refs,
                   'errors': errors},
                  f, ensure_ascii=False, indent=1)

    # GalTransl:去重日文
    seen = {}
    gt = []
    for r in tc_refs:
        if not r['has_jp']:
            continue
        t = r['text']
        if t in seen:
            continue
        seen[t] = len(gt)
        gt.append(dict(name='', message=t))
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, ensure_ascii=False, indent=1)

    # 统计报告
    total_tc = len(tc_refs)
    jp_tc    = sum(1 for r in tc_refs if r['has_jp'])
    uniq_tc  = len(set(r['text'] for r in tc_refs))
    jp_uniq  = len(seen)
    op_dist  = Counter(r['opcode'] for r in tc_refs)

    lines = []
    lines.append(f'=== {name} ===')
    lines.append(f'file size       : {os.path.getsize(path):#x}')
    lines.append(f'str_size        : {h["str_size"]:#x}  pool entries: {len(starts)}')
    lines.append(f'TABLE_A count   : {h["ta_count"]}')
    lines.append(f'TABLE_B count   : {h["tb_count"]}')
    lines.append(f'TABLE_C count   : {h["tc_count"]}')
    lines.append(f'')
    lines.append(f'-- string refs in TABLE_C --')
    lines.append(f'total           : {total_tc}')
    lines.append(f'contains JP     : {jp_tc}')
    lines.append(f'unique text     : {uniq_tc}')
    lines.append(f'unique JP text  : {jp_uniq}   <-- GalTransl output count')
    lines.append(f'errors          : {len(errors)}')
    lines.append(f'')
    lines.append(f'-- opcode distribution in TC string refs --')
    for op, c in op_dist.most_common():
        lines.append(f'  {op:#010x} : {c}')
    lines.append(f'')
    lines.append(f'-- first 8 JP samples --')
    shown = 0
    for r in tc_refs:
        if r['has_jp']:
            t = r['text'][:60].replace('\n', '\\n')
            lines.append(f'  tc#{r["tc_index"]:<6d} str_off={r["str_off"]:#07x}  {t!r}')
            shown += 1
            if shown >= 8: break
    report = '\n'.join(lines)
    with open(stats_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(report)
    print(f'\n  output: {gt_path}')
    print(f'          {raw_path}')
    print(f'          {stats_path}\n')


def selfcheck(path):
    """验证所有 bit0=1 指令指向的偏移都是合法的 \0 分隔字符串起点"""
    with open(path, 'rb') as f:
        data = f.read()
    h = parse_header(data)
    tc_base = h['tc_off']
    str_base = h['str_off']
    n_ref = 0
    mismatch = 0
    for i in range(h['tc_count']):
        off = tc_base + i * 8
        if data[off] & 1 == 0:
            continue
        n_ref += 1
        str_off = struct.unpack_from('<i', data, off + 4)[0]
        if str_off == -1:
            continue
        abs_pos = str_base + str_off
        if abs_pos != str_base and data[abs_pos - 1] != 0:
            mismatch += 1; continue
        try:
            end = data.index(b'\x00', abs_pos)
            data[abs_pos:end].decode('cp932')
        except (ValueError, UnicodeDecodeError):
            mismatch += 1
    status = 'OK' if mismatch == 0 else 'FAIL'
    print(f'[selfcheck {os.path.basename(path):20s}] refs={n_ref:<6d} mismatch={mismatch}  {status}')


def _expand_args(args):
    """将 args 展开为 .fbx 文件列表;支持:
       - 目录        → 扫目录下所有 *.fbx
       - 通配符       → 展开
       - 单个文件     → 直接加入
    """
    import glob
    out = []
    for a in args:
        if os.path.isdir(a):
            out.extend(sorted(glob.glob(os.path.join(a, '*.fbx'))))
            out.extend(sorted(glob.glob(os.path.join(a, '*.FBX'))))
        elif any(c in a for c in '*?[]'):
            out.extend(sorted(glob.glob(a)))
        else:
            out.append(a)
    # 去重保序
    seen = set(); uniq = []
    for f in out:
        if f not in seen:
            seen.add(f); uniq.append(f)
    return uniq


if __name__ == '__main__':
    # 用法:
    #   python gsx1_extract.py                         (默认样本)
    #   python gsx1_extract.py <文件或目录> [输出目录]
    #   python gsx1_extract.py file1.fbx file2.fbx ... [输出目录]
    #
    # 约定: 最后一个参数如果是目录 "路径" 且不存在或不含 fbx,作为 out_dir
    args = sys.argv[1:]
    if not args:
        files = [
            '/mnt/user-data/uploads/sce01.fbx',
            '/mnt/user-data/uploads/memories.fbx',
        ]
        out_dir = '/home/claude/out'
    else:
        # 最后一个参数:若不是 .fbx 且不是已有目录(或是不存在的目录名),视为 out_dir
        last = args[-1]
        if (not last.lower().endswith('.fbx')) and \
           (not os.path.isfile(last)) and \
           (not (os.path.isdir(last) and
                 any(f.lower().endswith('.fbx') for f in os.listdir(last)))):
            out_dir = last
            files = _expand_args(args[:-1])
        else:
            files = _expand_args(args)
            out_dir = './out'

    os.makedirs(out_dir, exist_ok=True)
    print(f'输入 {len(files)} 个文件,输出到 {out_dir}')
    for fp in files:
        print(f'  - {fp}')
    print()

    for fp in files:
        try:
            extract(fp, out_dir)
        except Exception as e:
            print(f'  !! 跳过 {os.path.basename(fp)}: {type(e).__name__}: {e}')
            # 额外 dump 前 64 字节供后续分析
            try:
                with open(fp, 'rb') as f:
                    head = f.read(64)
                print(f'     前 64 字节 hex:')
                print(f'     {head[:32].hex(" ")}')
                print(f'     {head[32:64].hex(" ")}')
            except Exception:
                pass
            print()
    print()
    for fp in files:
        try:
            selfcheck(fp)
        except Exception as e:
            print(f'[selfcheck {os.path.basename(fp):20s}] SKIP ({type(e).__name__})')
