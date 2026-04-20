# -*- coding: utf-8 -*-
"""
dac_inject.py — 月下の契り / DPK引擎 .dac/.dacz 脚本文本注入器

输入:
  - 原始 .dac/.dacz 文件
  - 翻译后的 JSON (GalTransl 格式)
  - 提取时生成的 .meta.json

输出:
  - 注入后的 .dac/.dacz 文件 (CP932 编码)

注入规则:
  - 只替换正文行 (line_no 行), 不动其他指令/空行/注释
  - 如果原行有立绘前缀 (prefix), 译文前自动拼回去
  - 说话人行不动 (orig_name_raw 原样保留, 不翻译)
  - 译文若含换行, 强制替换为全角空格 (防止破坏行结构)
  - 译文必须可 CP932 编码; 不可编码字符会报错列出

Round-trip:
  extract -> inject 空改 -> 结果与原文 byte-exact 一致
"""
import os, sys, json, argparse


def encode_cp932_safe(text: str, line_no: int) -> bytes:
    """编码 CP932, 不能编码时抛出详细错误"""
    try:
        return text.encode('cp932')
    except UnicodeEncodeError as e:
        bad = text[e.start:e.end]
        raise ValueError(
            f'line {line_no+1}: CP932 无法编码字符 {bad!r} '
            f'(U+{ord(bad[0]):04X}) 在 {text!r}'
        )


def inject_file(dac_path: str, json_path: str, meta_path: str, out_path: str,
                verify: bool = False):
    # 读原文件
    with open(dac_path, 'rb') as f:
        raw = f.read()
    text = raw.decode('cp932')
    lines = text.split('\r\n')

    # 读翻译 + meta
    with open(json_path, 'r', encoding='utf-8') as f:
        translations = json.load(f)
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    entries = meta['entries']

    # id -> translation
    tr_map = {it['id']: it for it in translations}

    # 清洗 + 替换
    errors = []
    replaced = 0
    for e in entries:
        tr = tr_map.get(e['id'])
        if tr is None:
            errors.append(f"id={e['id']} 翻译缺失")
            continue

        new_msg = tr.get('message', '')
        # 清洗换行: 全部替换为全角空格, 防止破坏行结构
        new_msg = new_msg.replace('\r\n', '\u3000').replace('\n', '\u3000').replace('\r', '\u3000')

        # 拼回立绘前缀
        prefix = e.get('prefix', '')
        full_line = prefix + new_msg

        # 编码校验
        try:
            encode_cp932_safe(full_line, e['line_no'])
        except ValueError as ex:
            errors.append(str(ex))
            continue

        lines[e['line_no']] = full_line
        replaced += 1

    if errors:
        print(f'[ERROR] 注入失败 {len(errors)} 处:', file=sys.stderr)
        for msg in errors[:20]:
            print(f'  {msg}', file=sys.stderr)
        if len(errors) > 20:
            print(f'  ... 还有 {len(errors)-20} 条', file=sys.stderr)
        return False

    # 重新拼接
    new_text = '\r\n'.join(lines)
    new_raw = new_text.encode('cp932')

    with open(out_path, 'wb') as f:
        f.write(new_raw)

    if verify:
        if new_raw == raw:
            print(f'[VERIFY] {os.path.basename(dac_path)}: byte-exact match ✓')
        else:
            # 找第一个不同
            n = min(len(raw), len(new_raw))
            diff_at = None
            for i in range(n):
                if raw[i] != new_raw[i]:
                    diff_at = i
                    break
            print(f'[VERIFY] {os.path.basename(dac_path)}: DIFF '
                  f'(orig={len(raw)}B new={len(new_raw)}B first_diff=0x{diff_at:x if diff_at else 0})')
            return False

    print(f'[OK] {dac_path} -> {out_path}  替换 {replaced}/{len(entries)} 条')
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='原始 .dac/.dacz 文件 或 目录')
    ap.add_argument('json', help='翻译 JSON 路径 或 目录')
    ap.add_argument('-o', '--output', required=True, help='输出路径 (文件或目录)')
    ap.add_argument('--meta', help='元信息路径 (默认 json + .meta.json)')
    ap.add_argument('--verify', action='store_true', help='round-trip 校验: 注入后比对原文')
    args = ap.parse_args()

    if os.path.isfile(args.input):
        meta = args.meta or (args.json + '.meta.json')
        ok = inject_file(args.input, args.json, meta, args.output, verify=args.verify)
        sys.exit(0 if ok else 1)
    else:
        os.makedirs(args.output, exist_ok=True)
        ok_all = True
        for name in sorted(os.listdir(args.input)):
            if not (name.endswith('.dac') or name.endswith('.dacz')):
                continue
            src = os.path.join(args.input, name)
            js = os.path.join(args.json, name + '.json')
            meta = js + '.meta.json'
            if not os.path.exists(js):
                print(f'[SKIP] {name}: 翻译缺失')
                continue
            out = os.path.join(args.output, name)
            ok = inject_file(src, js, meta, out, verify=args.verify)
            ok_all = ok_all and ok
        sys.exit(0 if ok_all else 1)


if __name__ == '__main__':
    main()
