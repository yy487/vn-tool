#!/usr/bin/env python3
"""BONDAGE 批量处理 - 通用路径解析 + 批量提取/注入"""
import sys, os, glob, json
from collections import Counter

def resolve_inputs(path_arg: str, ext: str = '.bin') -> list:
    """把一个路径参数解析成文件列表
    支持: 单文件 / 目录 / glob 通配符
    """
    # 通配符
    if any(c in path_arg for c in '*?['):
        return sorted(glob.glob(path_arg))
    # 目录
    if os.path.isdir(path_arg):
        return sorted(
            os.path.join(path_arg, f)
            for f in os.listdir(path_arg)
            if f.lower().endswith(ext)
        )
    # 单文件
    if os.path.isfile(path_arg):
        return [path_arg]
    return []


def batch_extract(input_arg: str, out_dir: str, merge_names: bool = True):
    """批量提取
    input_arg: bin 文件/目录/通配符
    out_dir:   输出目录 (JSON 放这里)
    merge_names: 是否合并所有文件的 name 表为一份全局表
    """
    import bondage_extract as be

    inputs = resolve_inputs(input_arg, '.bin')
    if not inputs:
        print(f"[ERR] 未找到任何 .bin 文件: {input_arg}")
        return

    os.makedirs(out_dir, exist_ok=True)
    print(f"[batch] 输入 {len(inputs)} 个文件 → {out_dir}")

    merged_names = Counter()   # name → 出现次数 (跨文件累加)
    total_entries = 0
    total_paired  = 0
    failed = []

    for bin_path in inputs:
        stem = os.path.splitext(os.path.basename(bin_path))[0]
        json_out = os.path.join(out_dir, stem + '.json')
        try:
            result = be.extract(bin_path)
        except Exception as e:
            print(f"  ✗ {stem}: {e}")
            failed.append(bin_path)
            continue

        entries = result['entries']
        # 构造输出 JSON
        json_data = []
        for e in entries:
            item = {'id': e['id'], 'pc': e['pc'], 'sub': e['sub'],
                    'kind': e['type'], 'text_off': e['text_off']}
            if e.get('name'):
                item['name'] = e['name']
                item['name_pc'] = e['name_pc']
                item['name_text_off'] = e['name_text_off']
                merged_names[e['name']] += 1
            item['message'] = e['message']
            item['src_msg'] = e['message']
            json_data.append(item)

        with open(json_out, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)

        n_pair = sum(1 for e in entries if e.get('name'))
        total_entries += len(json_data)
        total_paired  += n_pair
        print(f"  ✓ {stem}: {len(json_data):4d} 条 ({n_pair} 配对)")

        # 单文件 name 表 (若不合并或作为备份)
        if not merge_names:
            ind_names = Counter(e.get('name') for e in entries if e.get('name'))
            nt = {n: {'count': c, 'translation': n} for n, c in ind_names.most_common()}
            with open(os.path.join(out_dir, stem + '_names.json'),
                      'w', encoding='utf-8') as f:
                json.dump(nt, f, ensure_ascii=False, indent=2)

    # 合并后的全局 name 表
    if merge_names and merged_names:
        name_table = {n: {'count': c, 'translation': n}
                      for n, c in merged_names.most_common()}
        path = os.path.join(out_dir, '_names.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(name_table, f, ensure_ascii=False, indent=2)
        print(f"\n[global name 表] {len(name_table)} 个唯一说话人 → {path}")
        for n, info in list(name_table.items())[:10]:
            print(f"  {info['count']:5d}x  {n!r}")

    print(f"\n[summary] 成功 {len(inputs)-len(failed)}/{len(inputs)}, "
          f"总文本 {total_entries} 条 ({total_paired} 配对)")
    if failed:
        print(f"[failed] {len(failed)} 个文件:")
        for f in failed: print(f"  {f}")


def batch_inject(bin_input: str, json_input: str, out_dir: str,
                 name_table: str = None, mode: str = 'varlen'):
    """批量注入
    bin_input:  原 bin 文件/目录/通配符
    json_input: 翻译后 JSON 目录 (要与 bin stem 对应)
    out_dir:    注入后 bin 输出目录
    name_table: 全局 name 表路径; None 则自动查 json_input/_names.json
    mode:       'varlen' 变长 / 'fixed' 等长
    """
    import bondage_inject as bi

    bins = resolve_inputs(bin_input, '.bin')
    if not bins:
        print(f"[ERR] 未找到 .bin: {bin_input}"); return

    os.makedirs(out_dir, exist_ok=True)

    # 解析 JSON 目录
    if os.path.isdir(json_input):
        json_dir = json_input
    else:
        json_dir = os.path.dirname(json_input) or '.'

    # 自动查找全局 name 表
    if name_table is None:
        guess = os.path.join(json_dir, '_names.json')
        if os.path.exists(guess):
            name_table = guess
            print(f"[name] 使用全局 name 表: {name_table}")

    print(f"[batch] 注入 {len(bins)} 个文件 → {out_dir}  (模式: {mode})")
    ok, fail, skip = 0, 0, 0
    size_delta = 0
    all_fix = {}  # {bin_stem: [fix_records...]}

    for bin_path in bins:
        stem = os.path.splitext(os.path.basename(bin_path))[0]
        json_path = os.path.join(json_dir, stem + '.json')
        if not os.path.exists(json_path):
            print(f"  - {stem}: 无对应 JSON, 跳过")
            skip += 1
            continue
        out_path = os.path.join(out_dir, os.path.basename(bin_path))
        try:
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                fix_records = bi.inject(bin_path, json_path, out_path,
                                         name_table, mode=mode)
            orig_size = os.path.getsize(bin_path)
            new_size  = os.path.getsize(out_path)
            delta = new_size - orig_size
            size_delta += delta
            sign = '+' if delta >= 0 else ''
            fix_info = ''
            if fix_records:
                all_fix[stem] = fix_records
                total_overflow = sum(r['overflow'] for r in fix_records)
                fix_info = f"  ⚠ 截断 {len(fix_records)} 条 溢出 {total_overflow} B"
            print(f"  ✓ {stem}: {orig_size} → {new_size} B ({sign}{delta}){fix_info}")
            ok += 1
        except Exception as e:
            print(f"  ✗ {stem}: {e}")
            fail += 1

    # 汇总所有截断记录到全局 _fix.json
    if all_fix:
        global_fix_path = os.path.join(out_dir, '_fix.json')
        total_entries = sum(len(v) for v in all_fix.values())
        total_overflow = sum(r['overflow'] for recs in all_fix.values() for r in recs)
        with open(global_fix_path, 'w', encoding='utf-8') as f:
            json.dump(all_fix, f, ensure_ascii=False, indent=2)
        print(f"\n[截断汇总] {len(all_fix)} 个文件共 {total_entries} 条截断, "
              f"总溢出 {total_overflow} B → {global_fix_path}")
        # 按溢出字节数排名前 10 提示
        flat = [(stem, r) for stem, recs in all_fix.items() for r in recs]
        flat.sort(key=lambda x: -x[1]['overflow'])
        print(f"[溢出 TOP 10]")
        for stem, r in flat[:10]:
            name = f"[{r['name']}] " if r['name'] else ''
            print(f"  {stem} text_off={r['text_off']:#x} +{r['overflow']:3d}B "
                  f"{name}{r['trans_text'][:40]}")

    print(f"\n[summary] 成功 {ok}, 失败 {fail}, 跳过 {skip}, 总大小变化 {size_delta:+d} B")


def batch_roundtrip(bin_input: str):
    """批量 round-trip 测试"""
    import bondage_extract as be
    import bondage_inject as bi
    import io, contextlib

    bins = resolve_inputs(bin_input, '.bin')
    if not bins:
        print(f"[ERR] 未找到 .bin: {bin_input}"); return

    print(f"[roundtrip] 测试 {len(bins)} 个文件")
    passed, failed = 0, 0
    for bin_path in bins:
        stem = os.path.basename(bin_path)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ok = bi.roundtrip_test(bin_path)
            if ok:
                print(f"  ✓ {stem}")
                passed += 1
            else:
                print(f"  ✗ {stem}")
                print('\n'.join('    ' + l for l in buf.getvalue().splitlines()[-5:]))
                failed += 1
        except Exception as e:
            print(f"  ✗ {stem}: {e}")
            failed += 1

    print(f"\n[summary] PASS {passed}/{len(bins)}")


USAGE = """用法:
  extract:    python bondage_batch.py extract   <bin_path> <out_json_dir>
  inject:     python bondage_batch.py inject    <bin_path> <json_dir> <out_bin_dir> [--fixed]
  roundtrip:  python bondage_batch.py roundtrip <bin_path>

<bin_path> / <json_dir> 可以是:
  - 单个文件:  0081.bin
  - 目录:      ./scripts/
  - 通配符:    'data/*.bin'  (记得加引号避免 shell 展开)

extract: 自动生成 <out_json_dir>/_names.json 全局说话人表
inject:  自动读取 <json_dir>/_names.json 做 name 翻译
         --fixed 开启等长模式 (保持原偏移, 超长截断)
         等长模式会汇总所有截断记录到 <out_bin_dir>/_fix.json"""


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(USAGE); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'extract' and len(sys.argv) == 4:
        batch_extract(sys.argv[2], sys.argv[3])
    elif cmd == 'inject' and len(sys.argv) in (5, 6):
        mode = 'varlen'
        if len(sys.argv) == 6:
            if sys.argv[5] == '--fixed':
                mode = 'fixed'
            else:
                print(f"未知参数: {sys.argv[5]}"); print(USAGE); sys.exit(1)
        batch_inject(sys.argv[2], sys.argv[3], sys.argv[4], mode=mode)
    elif cmd == 'roundtrip' and len(sys.argv) == 3:
        batch_roundtrip(sys.argv[2])
    else:
        print(USAGE); sys.exit(1)
