#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scr2_inject.py — Studio e.go! 'SCR ' v1 文本等长注入器

策略: 等长替换。译文 cp932 字节数 ≤ 原文字节数, 不足部分用半角空格补齐。
超长直接报错跳过该条。

子命令:
    single          注入单个 scr
    batch           批量注入整个目录, 无 JSON 的 scr 原样复制
    export_overflow 扫一遍, 把所有超长条目导出成 fix.json (不写注入文件)
    apply_fix       拿改好的 fix.json 回填到源 JSON 目录

用法:
    python scr2_inject.py single Ay_01.scr ay_01.json Ay_01_new.scr
    python scr2_inject.py batch  scr_dir/  json_dir/  out_dir/
    python scr2_inject.py export_overflow scr_dir/ json_dir/ fix.json
    python scr2_inject.py apply_fix fix.json json_dir/

修 fix.json 流程:
  1. python scr2_inject.py export_overflow scr/ json/ fix.json
  2. 手动编辑 fix.json, 只改每条的 "trans" 字段, 让译文变短
     (其它字段是定位用, 不要改)
  3. python scr2_inject.py apply_fix fix.json json/
  4. python scr2_inject.py batch scr/ json/ out/
"""
import os, sys, json, shutil, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scr2_codec import parse_header


def _truncate_cp932(buf: bytes, max_len: int) -> bytes:
    """把 cp932 字节流按字符边界截断到不超过 max_len 字节.

    cp932 是变长编码: ASCII 1B, 双字节字符首字节 0x81-0x9F 或 0xE0-0xFC。
    截断时如果 max_len 落在双字节字符中间, 必须再退一格。
    """
    if len(buf) <= max_len:
        return buf
    # 从头扫到 max_len, 记录每个合法的字符边界
    i = 0
    last_good = 0
    while i < max_len:
        b = buf[i]
        if (0x81 <= b <= 0x9f) or (0xe0 <= b <= 0xfc):
            # 双字节字符
            if i + 2 > max_len:
                break  # 装不下整个双字节, 停在 last_good
            i += 2
        else:
            i += 1
        last_good = i
    return buf[:last_good]


def inject_one(scr_data: bytes, trans: list):
    """返回 (新字节, ok数, fail数, 报错列表, 超长条目列表).

    超长条目: 按 cp932 字符边界截断后写入 (不丢, 但显示会被切尾),
              同时记录到 overflow 列表供后续 fix.json 修正。
    cp932 编码失败 (含非 cp932 字符): 直接跳过, 写入 errs。
    """
    parse_header(scr_data)
    out = bytearray(scr_data)
    ok = fail = 0
    errs = []
    overflow = []
    for it in trans:
        if 'message' not in it or 'pos' not in it or 'len' not in it:
            continue
        pos = int(it['pos'], 0) if isinstance(it['pos'], str) else it['pos']
        orig_len = it['len']
        msg = it['message']
        try:
            new = msg.encode('cp932')
        except UnicodeEncodeError as e:
            errs.append(f'id={it.get("id")} cp932 编码失败: {e}')
            fail += 1
            continue
        if len(new) > orig_len:
            # 截断写入 + 记录到 overflow
            truncated = _truncate_cp932(new, orig_len)
            padded = truncated + b' ' * (orig_len - len(truncated))
            out[pos:pos + orig_len] = padded
            overflow.append({
                'id': it.get('id'),
                'pos': it['pos'] if isinstance(it['pos'], str) else f'0x{pos:x}',
                'len': orig_len,
                'trans': msg,
                'trans_bytes': len(new),
                'over': len(new) - orig_len,
                '_name': it.get('name'),
            })
            fail += 1
            continue
        if len(new) < orig_len:
            new = new + b' ' * (orig_len - len(new))
        out[pos:pos + orig_len] = new
        ok += 1
    return bytes(out), ok, fail, errs, overflow
    return bytes(out), ok, fail, errs, overflow


# ---- single / batch (实际写盘) -------------------------------------------

def cmd_single(args):
    d = open(args.scr, 'rb').read()
    trans = json.load(open(args.json, encoding='utf-8'))
    new, ok, fail, errs, overflow = inject_one(d, trans)
    for e in errs:
        print(f'  [!] {e}')
    for o in overflow:
        print(f'  [超长] id={o["id"]} pos={o["pos"]} {o["trans_bytes"]}>{o["len"]} (+{o["over"]}): {o["trans"][:30]!r}')
    with open(args.out, 'wb') as f:
        f.write(new)
    print(f'[✓] {args.scr} → {args.out}: {ok} 注入, {fail} 失败')


def cmd_batch(args):
    os.makedirs(args.outdir, exist_ok=True)
    n_inj = n_copy = n_fail = 0
    total_ok = total_fail = 0
    for root, _, files in os.walk(args.scrdir):
        for fn in files:
            if not fn.lower().endswith('.scr'):
                continue
            scr_path = os.path.join(root, fn)
            rel = os.path.relpath(scr_path, args.scrdir)
            out_path = os.path.join(args.outdir, rel)
            os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
            json_path = os.path.join(args.jsondir,
                                     os.path.splitext(rel)[0] + '.json')
            if not os.path.exists(json_path):
                shutil.copyfile(scr_path, out_path)
                n_copy += 1
                continue
            try:
                d = open(scr_path, 'rb').read()
                trans = json.load(open(json_path, encoding='utf-8'))
                new, ok, fail, errs, overflow = inject_one(d, trans)
                with open(out_path, 'wb') as f:
                    f.write(new)
                n_inj += 1
                total_ok += ok
                total_fail += fail
            except Exception as e:
                print(f'[!!] {rel}: {e}')
                n_fail += 1
                shutil.copyfile(scr_path, out_path)
    print(f'\n✓ 注入完成: {n_inj} 个脚本注入 ({total_ok} 条 ok, {total_fail} 失败)')
    print(f'  无 JSON 直接复制: {n_copy}, 异常: {n_fail}')


# ---- export_overflow -----------------------------------------------------

def cmd_export_overflow(args):
    """扫描所有 scr+json, 收集超长条目, 不写任何注入文件.

    输出 fix.json 是一个列表, 每条:
      rel          源 JSON 相对路径 (回填用, 不要改)
      id           条目 id (回填用, 不要改)
      pos          原文位置 (回填校验用, 不要改)
      len          原文字节上限 (不要改)
      name         说话人 (若有, 仅供翻译参考)
      trans        当前译文 (★ 只改这里, 改成更短的版本)
      trans_bytes  当前译文 cp932 字节数
      over         超出字节数 (削减目标)
    """
    all_overflow = []
    n_scr = 0
    for root, _, files in os.walk(args.scrdir):
        for fn in files:
            if not fn.lower().endswith('.scr'):
                continue
            scr_path = os.path.join(root, fn)
            rel = os.path.relpath(scr_path, args.scrdir)
            json_rel = os.path.splitext(rel)[0] + '.json'
            json_path = os.path.join(args.jsondir, json_rel)
            if not os.path.exists(json_path):
                continue
            try:
                d = open(scr_path, 'rb').read()
                trans = json.load(open(json_path, encoding='utf-8'))
            except Exception as e:
                print(f'[!] {rel}: {e}')
                continue
            n_scr += 1
            _, _, _, _, overflow = inject_one(d, trans)
            for o in overflow:
                entry = {
                    'rel': json_rel.replace(os.sep, '/'),
                    'id': o['id'],
                    'pos': o['pos'],
                    'len': o['len'],
                }
                if o.get('_name'):
                    entry['name'] = o['_name']
                entry['trans'] = o['trans']
                entry['trans_bytes'] = o['trans_bytes']
                entry['over'] = o['over']
                all_overflow.append(entry)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(all_overflow, f, ensure_ascii=False, indent=2)
    print(f'✓ 扫描 {n_scr} 个脚本, 导出 {len(all_overflow)} 条超长 → {args.out}')
    if all_overflow:
        overs = [x['over'] for x in all_overflow]
        print(f'  超出字节数: min={min(overs)} max={max(overs)} 平均={sum(overs)/len(overs):.1f}')


# ---- apply_fix -----------------------------------------------------------

def cmd_apply_fix(args):
    """把 fix.json 里改好的 trans 回填到源 JSON 目录.

    匹配键: (rel, id)。pos 做 sanity check 防止串号。
    只改对应条目的 message 字段。
    """
    fixes = json.load(open(args.fix, encoding='utf-8'))
    by_rel = {}
    for f in fixes:
        by_rel.setdefault(f['rel'], []).append(f)

    n_files = n_apply = n_skip = n_miss = 0
    for rel, entries in by_rel.items():
        json_path = os.path.join(args.jsondir, rel.replace('/', os.sep))
        if not os.path.exists(json_path):
            print(f'[!] 源 JSON 不存在: {rel}')
            n_miss += len(entries)
            continue
        data = json.load(open(json_path, encoding='utf-8'))
        by_id = {it.get('id'): it for it in data}
        changed = False
        for f in entries:
            it = by_id.get(f['id'])
            if it is None:
                print(f'[!] {rel}: id={f["id"]} 不存在')
                n_miss += 1
                continue
            if str(it.get('pos')) != str(f.get('pos')):
                print(f'[!] {rel} id={f["id"]}: pos 不匹配 ({it.get("pos")} vs {f.get("pos")})')
                n_miss += 1
                continue
            try:
                nb = len(f['trans'].encode('cp932'))
            except UnicodeEncodeError as e:
                print(f'[!] {rel} id={f["id"]}: cp932 失败 {e}')
                n_skip += 1
                continue
            if nb > f['len']:
                print(f'[!] {rel} id={f["id"]}: 仍超长 {nb}>{f["len"]}, 跳过')
                n_skip += 1
                continue
            it['message'] = f['trans']
            changed = True
            n_apply += 1
        if changed:
            with open(json_path, 'w', encoding='utf-8') as g:
                json.dump(data, g, ensure_ascii=False, indent=2)
            n_files += 1
    print(f'✓ 回填完成: {n_apply} 条写入, {n_files} 个文件被修改')
    if n_skip:
        print(f'  仍超长跳过: {n_skip}')
    if n_miss:
        print(f'  匹配失败: {n_miss}')


# ---- CLI ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('single')
    p.add_argument('scr'); p.add_argument('json'); p.add_argument('out')
    p.set_defaults(func=cmd_single)

    p = sub.add_parser('batch')
    p.add_argument('scrdir'); p.add_argument('jsondir'); p.add_argument('outdir')
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser('export_overflow', help='导出所有超长条目到 fix.json')
    p.add_argument('scrdir')
    p.add_argument('jsondir')
    p.add_argument('out')
    p.set_defaults(func=cmd_export_overflow)

    p = sub.add_parser('apply_fix', help='把改好的 fix.json 回填到 jsondir')
    p.add_argument('fix')
    p.add_argument('jsondir')
    p.set_defaults(func=cmd_apply_fix)

    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
