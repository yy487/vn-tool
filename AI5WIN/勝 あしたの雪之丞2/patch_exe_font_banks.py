#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Patch Ai5win.exe font_size_array for AI5WIN bitmap font banks.

反汇编确认：EXE .data 段存在 font_size_array，文件偏移 0x532C4。
数组布局为 4 组，每组 12 字节：TBL/FNT/MSK 的解压后 raw size。

  group 0: FONT00  TBL,FNT,MSK
  group 1: FONT01  TBL,FNT,MSK
  group 2: FONT02  TBL,FNT,MSK
  group 3: FONTHAN TBL,FNT,MSK

本脚本读取 font_gen.py 生成的 build_manifest.json，把各 bank 的 raw size
写回 EXE 对应位置。未在 manifest 中出现或只是 copied_original 的 bank 默认保持原值。

默认会做 offset 合理性校验：
  1. 0x532C4 处旧值应匹配已知原版 font raw size，或匹配 manifest.old，或已经等于 manifest 新值。
  2. FNT/MSK 必须相等，双字节 bank 必须是 26*26 的整数倍，FONTHAN 必须是 14*26 的整数倍。
校验失败默认拒绝写入；如确认目标 EXE 已经过其它补丁，可加 --force。

用法：
  python patch_exe_font_banks.py <Ai5win.exe> <build_manifest.json> [output.exe]
  python patch_exe_font_banks.py <Ai5win.exe> <build_manifest.json> --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import sys

FONT_SIZE_ARRAY_OFF = 0x532C4
BANK_ORDER = ["FONT00", "FONT01", "FONT02", "FONTHAN"]
FIELD_ORDER = ["tbl_raw_size", "fnt_raw_size", "msk_raw_size"]
FIELD_LABEL = ["TBL", "FNT", "MSK"]

# 从干净/常见原版 EXE 读到的 4 组 raw size。用于确认 0x532C4 确实是 font_size_array。
KNOWN_VANILLA_SIZES = {
    "FONT00": [12458, 4210128, 4210128],  # 6228 glyphs * 26 * 26; TBL 6228*2+2
    "FONT01": [2066, 709800, 709800],     # 1050 slots * 26 * 26
    "FONT02": [1638, 574600, 574600],     # 850 slots * 26 * 26
    "FONTHAN": [138, 24388, 24388],       # 67 slots * 14 * 26
}

GLYPH_AREA = {
    "FONT00": 26 * 26,
    "FONT01": 26 * 26,
    "FONT02": 26 * 26,
    "FONTHAN": 14 * 26,
}


def _load_manifest(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "banks" not in data or not isinstance(data["banks"], dict):
        raise ValueError("manifest 缺少 banks 字段，确认传入的是 build_manifest.json")
    return data


def _bank_sizes(info: dict) -> list[int] | None:
    """Return [tbl,fnt,msk] raw sizes, or None if this bank should be kept unchanged."""
    if info.get("copied_original"):
        return None
    sizes = []
    for key in FIELD_ORDER:
        v = info.get(key)
        if not isinstance(v, int) or v <= 0:
            raise ValueError(f"manifest bank 缺少有效 {key}: {info!r}")
        sizes.append(v)
    return sizes


def _manifest_old_sizes(info: dict | None) -> list[int] | None:
    if not info or not isinstance(info, dict):
        return None
    old = info.get("old")
    if not isinstance(old, dict):
        return None
    vals = []
    for key in FIELD_ORDER:
        v = old.get(key)
        if not isinstance(v, int) or v <= 0:
            return None
        vals.append(v)
    return vals


def _validate_size_shape(bank: str, sizes: list[int], *, what: str) -> list[str]:
    errs: list[str] = []
    tbl, fnt, msk = sizes
    area = GLYPH_AREA[bank]
    if tbl < 2 or (tbl % 2) != 0:
        errs.append(f"{bank} {what}: TBL size 异常: {tbl}")
    if fnt != msk:
        errs.append(f"{bank} {what}: FNT/MSK size 不相等: {fnt}/{msk}")
    if (fnt % area) != 0:
        errs.append(f"{bank} {what}: FNT size 不是 glyph_area({area}) 整数倍: {fnt}")
    if (msk % area) != 0:
        errs.append(f"{bank} {what}: MSK size 不是 glyph_area({area}) 整数倍: {msk}")
    return errs


def _validate_offset(old_all: dict[str, list[int]], manifest: dict) -> list[str]:
    """Return warnings/errors proving whether 0x532C4 looks like the font size array."""
    errs: list[str] = []
    banks = manifest["banks"]

    vanilla_hits = 0
    plausible_hits = 0
    for bank in BANK_ORDER:
        old = old_all[bank]
        errs.extend(_validate_size_shape(bank, old, what="old"))
        if old == KNOWN_VANILLA_SIZES[bank]:
            vanilla_hits += 1
        if not _validate_size_shape(bank, old, what="old"):
            plausible_hits += 1

        info = banks.get(bank)
        new = _bank_sizes(info) if isinstance(info, dict) else None
        if new is not None:
            errs.extend(_validate_size_shape(bank, new, what="new"))

    # 最强确认：四组旧值都等于已知原版 raw size。
    if vanilla_hits == len(BANK_ORDER):
        return errs

    # 允许两种非原版情况：
    # 1. 已经 patch 过一次，old == manifest 新值。
    # 2. old == manifest.old，即 EXE 和本次原始 font 目录一致。
    explain = []
    for bank in BANK_ORDER:
        old = old_all[bank]
        info = banks.get(bank)
        if not isinstance(info, dict) or info.get("copied_original"):
            continue
        new = _bank_sizes(info)
        manifest_old = _manifest_old_sizes(info)
        if new and old == new:
            continue
        if manifest_old and old == manifest_old:
            continue
        if old == KNOWN_VANILLA_SIZES[bank]:
            continue
        explain.append(f"{bank}: old={old}, manifest_old={manifest_old}, new={new}, vanilla={KNOWN_VANILLA_SIZES[bank]}")

    if explain:
        errs.append(
            "0x532C4 处数据不是已知原版 size，也不匹配 manifest.old/new；"
            "为避免误 patch，默认拒绝写入。详情: " + " | ".join(explain)
        )
    elif plausible_hits < 3:
        errs.append("0x532C4 处只有少数组看起来像 font size，疑似 offset 不正确。")

    return errs


def patch_exe(src_exe: str, manifest_path: str, out_exe: str | None = None, *, dry_run: bool = False, force: bool = False) -> None:
    manifest = _load_manifest(manifest_path)
    banks = manifest["banks"]

    if out_exe is None:
        out_exe = src_exe + ".patched"

    with open(src_exe, "rb") as f:
        data = bytearray(f.read())

    need_len = FONT_SIZE_ARRAY_OFF + len(BANK_ORDER) * 12
    if len(data) < need_len:
        raise ValueError(f"EXE 太小，无法访问 font_size_array: size=0x{len(data):X}, need=0x{need_len:X}")

    old_all: dict[str, list[int]] = {}
    for bank_idx, bank in enumerate(BANK_ORDER):
        base = FONT_SIZE_ARRAY_OFF + bank_idx * 12
        old_all[bank] = list(struct.unpack_from("<III", data, base))

    validation_errors = _validate_offset(old_all, manifest)

    print(f"font_size_array file offset: 0x{FONT_SIZE_ARRAY_OFF:X}")
    print(f"source: {src_exe}")
    print(f"manifest: {manifest_path}")
    print("")

    if validation_errors:
        print("[validation]")
        for e in validation_errors:
            print(f"  ! {e}")
        if not force:
            print("\n校验未通过，未写入。确认目标 EXE 已经被其它补丁改过时，可加 --force。")
            return
        print("\n[force] 校验未通过但继续执行。")
        print("")
    else:
        print("[validation] OK: 0x532C4 的 4 组旧值符合 AI5WIN font_size_array 特征。")
        print("")

    changed = False
    for bank_idx, bank in enumerate(BANK_ORDER):
        base = FONT_SIZE_ARRAY_OFF + bank_idx * 12
        old = old_all[bank]
        info = banks.get(bank)
        if info is None:
            print(f"[{bank}] keep: manifest 中无此 bank，old {dict(zip(FIELD_LABEL, old))}")
            continue
        new = _bank_sizes(info)
        if new is None:
            print(f"[{bank}] keep: copied_original，old {dict(zip(FIELD_LABEL, old))}")
            continue

        print(f"[{bank}] @0x{base:X}")
        for label, ov, nv in zip(FIELD_LABEL, old, new):
            mark = "*" if ov != nv else " "
            print(f"  {mark} {label}: {ov} -> {nv}")
        if old != new:
            changed = True
            if not dry_run:
                struct.pack_into("<III", data, base, *new)

    if dry_run:
        print("\n[dry-run] 未写入文件")
        return

    if not changed:
        print("\n没有需要修改的 size 常量。")
        if src_exe != out_exe:
            shutil.copy2(src_exe, out_exe)
            print(f"copied: {out_exe}")
        return

    if os.path.abspath(src_exe) != os.path.abspath(out_exe):
        os.makedirs(os.path.dirname(out_exe) or ".", exist_ok=True)
    with open(out_exe, "wb") as f:
        f.write(data)
    print(f"\npatched: {out_exe}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Patch AI5WIN font_size_array for FONT00/FONT01/FONT02/FONTHAN")
    ap.add_argument("exe", help="input Ai5win.exe")
    ap.add_argument("manifest", help="build/DATA_FONT/build_manifest.json")
    ap.add_argument("output", nargs="?", help="output exe; default: <exe>.patched")
    ap.add_argument("--dry-run", action="store_true", help="print changes without writing")
    ap.add_argument("--force", action="store_true", help="write even if validation does not match known/manifest sizes")
    args = ap.parse_args()

    try:
        patch_exe(args.exe, args.manifest, args.output, dry_run=args.dry_run, force=args.force)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
