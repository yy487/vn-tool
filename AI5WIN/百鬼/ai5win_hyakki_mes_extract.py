#!/usr/bin/env python3
"""AI5WIN 百鬼 (Hyakki) MES 文本提取 -> GalTransl JSON.

用法:
  批量:  python ai5win_hyakki_mes_extract.py batch <mes_dir> <json_dir>
  单文件: python ai5win_hyakki_mes_extract.py single <in.MES> <out.json>

提取规则:
  - 只抓 opcode 0x01 TEXT 指令
  - 跳过不含 SJIS 双字节的纯 ASCII 字符串 (资源路径 .mam/.wav 等)
  - 每条 TEXT 独立输出，name 永远为 ""，不做任何合并
  - msg_idx 由最近一条 0x15 MESSAGE 指令的 id 决定
    (第一条 0x15 之前的初始化区 msg_idx = -1)
  - text_idx 是同一条 message 内所有 TEXT (含跳过的) 的 0-based 序号，
    重置条件只有 0x15，保证注入时一一对应
"""
import os, sys, json, glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ai5win_hyakki_mes_codec import (
    lzss_decompress, parse_mes_header, disassemble, get_message_id,
)


def _has_sjis(b: bytes) -> bool:
    i, n = 0, len(b)
    while i < n - 1:
        c1 = b[i]
        if (0x81 <= c1 <= 0x9F) or (0xE0 <= c1 <= 0xEF):
            if 0x40 <= b[i+1] <= 0xFC and b[i+1] != 0x7F:
                return True
        i += 1
    return False


def extract_one(file_bytes: bytes, filename: str) -> list:
    plain = lzss_decompress(file_bytes)
    count, first_offsets, bc_start = parse_mes_header(plain)
    if count == 0:
        return []

    instrs = disassemble(plain[bc_start:])
    entries = []
    msg_idx = -1
    text_idx = 0

    for ins in instrs:
        if ins.op == 0x15:
            msg_idx = get_message_id(ins)
            text_idx = 0
            continue
        if ins.op != 0x01:
            continue

        raw = ins.raw[1:-1]   # 去掉 opcode 字节 + 末尾 NUL
        if _has_sjis(raw):
            try:
                txt = raw.decode('cp932')
            except UnicodeDecodeError:
                txt = raw.decode('cp932', errors='replace')
            entries.append({
                'name':    '',
                'message': txt,
                'id':      f"{filename}#{msg_idx}#{text_idx}",
            })
        text_idx += 1   # 不管是否保留都递增

    return entries


def extract_batch(mes_dir: str, json_dir: str) -> None:
    os.makedirs(json_dir, exist_ok=True)
    mes_files = sorted(glob.glob(os.path.join(mes_dir, '*.MES')))
    total, story = 0, 0
    for p in mes_files:
        fn = os.path.basename(p)
        entries = extract_one(open(p, 'rb').read(), fn)
        if not entries:
            continue
        story += 1
        total += len(entries)
        out = os.path.join(json_dir, fn.replace('.MES', '.json'))
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"剧情 MES : {story} 个")
    print(f"共提取   : {total} 条文本 -> {json_dir}")


def extract_single(mes_path: str, json_path: str) -> None:
    fn = os.path.basename(mes_path)
    entries = extract_one(open(mes_path, 'rb').read(), fn)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"{fn}: {len(entries)} 条 -> {json_path}")


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd = sys.argv[1].lower()
    if cmd == 'batch':
        if len(sys.argv) != 4:
            print("usage: batch <mes_dir> <json_dir>"); sys.exit(1)
        extract_batch(sys.argv[2], sys.argv[3])
    elif cmd == 'single':
        if len(sys.argv) != 4:
            print("usage: single <in.MES> <out.json>"); sys.exit(1)
        extract_single(sys.argv[2], sys.argv[3])
    else:
        print(f"unknown cmd: {cmd}"); sys.exit(1)

if __name__ == '__main__':
    main()
