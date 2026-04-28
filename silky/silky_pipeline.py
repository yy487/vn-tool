"""silky_pipeline.py — Silky MES 一站式批量处理。

把 4 步流水线合成 2 个命令：

  unpack:  *.MES -> op.txt + translate.txt   (反汇编 + 提取)
  pack:    op.txt + translate.txt -> *.MES   (注入 + 汇编)

中间会产生 .op.txt 和 .translate.txt 两类文件。
.op.txt 是结构骨架，注入时不动它的指令流，只改它的 STR 参数行。
.translate.txt 是 GalTransl 风格的双行 ◇/◆ 文本，给译者改 ◆ 行。

CLI:
  python silky_pipeline.py unpack <MES目录> <工作目录>
    会在 <工作目录> 下生成:
      op/         反汇编 op.txt
      translate/  待翻译 translate.txt   <-- 把这一堆扔给 GalTransl

  python silky_pipeline.py pack <MES目录> <工作目录> <输出目录>
    会读 <工作目录>/op + <工作目录>/translate 注入译文，
    再把注入后的 op.txt 编回 *.MES，写到 <输出目录>。
"""

import argparse
import glob
import os
import sys

# 延迟导入避免命名冲突
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _strip_ext(name, exts):
    for e in exts:
        if name.lower().endswith(e.lower()):
            return name[:-len(e)]
    return os.path.splitext(name)[0]


def cmd_unpack(args):
    """MES 目录 -> 工作目录/op + 工作目录/translate"""
    import silky_op
    import silky_extract

    op_dir = os.path.join(args.workdir, "op")
    tr_dir = os.path.join(args.workdir, "translate")
    os.makedirs(op_dir, exist_ok=True)
    os.makedirs(tr_dir, exist_ok=True)

    files = sorted(glob.glob(os.path.join(args.mes_dir, "*.MES")))
    if not files:
        print(f"[!] {args.mes_dir} 下没有 .MES 文件")
        return 1

    print(f"[unpack] 找到 {len(files)} 个 .MES 文件")
    total_entries = 0

    for f in files:
        base = _strip_ext(os.path.basename(f), ['.MES'])
        op_path = os.path.join(op_dir, base + ".op.txt")
        tr_path = os.path.join(tr_dir, base + ".translate.txt")

        # 1. disassemble
        sm = silky_op.SilkyMesScript(f, op_path, encoding=args.encoding)
        sm.disassemble()

        # 2. extract
        n = silky_extract.extract_text(op_path, tr_path)
        total_entries += n

        print(f"  [+] {base}: {n} entries")

    print(f"[unpack] 完成 {len(files)} 个文件, 共 {total_entries} 条文本")
    print(f"[unpack] op.txt 在: {op_dir}")
    print(f"[unpack] translate.txt 在: {tr_dir}  <-- 翻译这里的 ◆ 行")
    return 0


def cmd_pack(args):
    """工作目录/op + 工作目录/translate -> 输出目录/*.MES"""
    import silky_op
    import silky_inject

    op_dir = os.path.join(args.workdir, "op")
    tr_dir = os.path.join(args.workdir, "translate")
    op2_dir = os.path.join(args.workdir, "op_injected")  # 中间产物
    os.makedirs(op2_dir, exist_ok=True)
    os.makedirs(args.output_dir, exist_ok=True)

    if not os.path.isdir(op_dir):
        print(f"[!] {op_dir} 不存在，请先 unpack")
        return 1
    if not os.path.isdir(tr_dir):
        print(f"[!] {tr_dir} 不存在，请先 unpack")
        return 1

    op_files = sorted(glob.glob(os.path.join(op_dir, "*.op.txt")))
    if not op_files:
        print(f"[!] {op_dir} 下没有 .op.txt")
        return 1

    print(f"[pack] 找到 {len(op_files)} 个 op.txt")
    total_entries = 0
    missing = []
    failed = []

    for op_path in op_files:
        base = _strip_ext(os.path.basename(op_path), ['.op.txt'])
        tr_path = os.path.join(tr_dir, base + ".translate.txt")
        if not os.path.isfile(tr_path):
            missing.append(base)
            continue

        op2_path = os.path.join(op2_dir, base + ".op.txt")
        out_mes = os.path.join(args.output_dir, base + ".MES")

        # 3. inject 译文
        try:
            n = silky_inject.import_text(op_path, tr_path, op2_path)
        except Exception as e:
            failed.append((base, f"inject: {e}"))
            continue

        # 4. assemble
        try:
            sm = silky_op.SilkyMesScript(out_mes, op2_path, encoding=args.encoding)
            sm.assemble()
        except Exception as e:
            failed.append((base, f"asm: {e}"))
            continue

        total_entries += n
        print(f"  [+] {base}: {n} entries -> {os.path.basename(out_mes)}")

    print(f"[pack] 成功 {len(op_files) - len(missing) - len(failed)} 个, 共注入 {total_entries} 条")
    if missing:
        print(f"[!] 缺译文 {len(missing)} 个: {missing[:5]}{'...' if len(missing)>5 else ''}")
    if failed:
        print(f"[!] 失败 {len(failed)} 个:")
        for n, err in failed[:5]:
            print(f"    {n}: {err}")
    print(f"[pack] 输出 .MES 在: {args.output_dir}")
    return 0 if not failed else 2


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Silky MES 一站式批量处理")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_u = sub.add_parser("unpack",
                         help="MES目录 -> 工作目录/op + 工作目录/translate")
    p_u.add_argument("mes_dir", help="包含原始 .MES 的目录")
    p_u.add_argument("workdir", help="工作目录（自动创建 op/ 和 translate/ 子目录）")
    p_u.add_argument("--encoding", default="cp932")
    p_u.set_defaults(func=cmd_unpack)

    p_p = sub.add_parser("pack",
                         help="工作目录/op + 工作目录/translate -> 输出目录/*.MES")
    p_p.add_argument("mes_dir", help="（占位，保持参数对齐；实际未使用）")
    p_p.add_argument("workdir", help="包含 op/ 和 translate/ 的工作目录")
    p_p.add_argument("output_dir", help="输出 .MES 目录")
    p_p.add_argument("--encoding", default="cp932")
    p_p.set_defaults(func=cmd_pack)

    args = ap.parse_args()
    sys.exit(args.func(args))
