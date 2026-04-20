#!/usr/bin/env python3
"""AI5WIN 百鬼 (Hyakki) GalTransl JSON -> MES 注入.

用法:
  批量注入:
    python ai5win_hyakki_mes_inject.py batch <orig_mes_dir> <json_dir> <out_mes_dir>

  单文件:
    python ai5win_hyakki_mes_inject.py single <orig.MES> <in.json> <out.MES>

  round-trip verify:
    python ai5win_hyakki_mes_inject.py verify <orig_mes_dir>

注入流程:
  1. 反汇编原 MES -> instrs
  2. 建 (msg_idx, text_idx) -> instr 索引
  3. 读 JSON，每条按 id 解析 (msg_idx, text_idx)，直接写入对应 TEXT 指令
     (name 字段忽略，只用 message)
  4. assemble() 自动修复所有 JUMP 和 first_offsets
  5. LZSS 压缩输出

字符替换:
  - 半角 ASCII 转全角 ASCII（空格 -> 全角空格）
  - 特殊符号表预留（百鬼暂未见 ♡♪，有需要在 SPECIAL_CHAR_MAP_ENCODE 补充）

注意:
  - 编码固定 CP932，不转 GBK（阶段 5 再做字体 hook）
  - TEXT 字符串中不能含 \\x00（会误判为 NUL 终止）
"""
import os, sys, json, glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ai5win_hyakki_mes_codec import (
    lzss_decompress, lzss_compress,
    parse_mes_header, build_mes_header,
    disassemble, assemble, pack_mes,
    get_message_id, set_text_string,
)

# 特殊符号替换表 (源字符 -> CP932 字节)，预留
SPECIAL_CHAR_MAP_ENCODE: dict = {
    # '♡': b'\xeb\xa1',
}


def halfwidth_to_fullwidth(s: str) -> str:
    out = []
    for ch in s:
        c = ord(ch)
        if c == 0x20:
            out.append('\u3000')
        elif 0x21 <= c <= 0x7E:
            out.append(chr(c - 0x21 + 0xFF01))
        else:
            out.append(ch)
    return ''.join(out)


def encode_text(s: str) -> bytes:
    for src, dst in SPECIAL_CHAR_MAP_ENCODE.items():
        s = s.replace(src, '\x00PLACEHOLDER\x00')
    s = halfwidth_to_fullwidth(s)
    try:
        return s.encode('cp932')
    except UnicodeEncodeError as e:
        raise ValueError(f"cannot encode to CP932: {s!r} ({e})")


# ───────────────────────────────────────────────
#  索引: (msg_idx, text_idx) -> instr
# ───────────────────────────────────────────────

def _has_sjis(b: bytes) -> bool:
    i, n = 0, len(b)
    while i < n - 1:
        c1 = b[i]
        if (0x81 <= c1 <= 0x9F) or (0xE0 <= c1 <= 0xEF):
            if 0x40 <= b[i+1] <= 0xFC and b[i+1] != 0x7F:
                return True
        i += 1
    return False


def build_text_index(instrs) -> dict:
    """返回 {(msg_idx, text_idx): instr}，所有 TEXT 条目都建索引（不过滤）."""
    idx = {}
    msg_idx = -1
    text_idx = 0
    for ins in instrs:
        if ins.op == 0x15:
            msg_idx = get_message_id(ins)
            text_idx = 0
            continue
        if ins.op == 0x01:
            idx[(msg_idx, text_idx)] = ins
            text_idx += 1
    return idx


# ───────────────────────────────────────────────
#  注入单个文件
# ───────────────────────────────────────────────

def inject_one(orig_bytes: bytes, entries: list, filename_for_err: str = '') -> bytes:
    """对一个 MES 的字节 + JSON 条目列表，返回新 MES 文件字节.

    每条 JSON entry 格式:
      {"name": "", "message": "...", "id": "FILE.MES#msg_idx#text_idx"}

    注入逻辑:
      - 从 id 解析出 (msg_idx, text_idx)
      - 直接在 text_index 里找到对应的 TEXT 指令，用 message 覆写
      - name 字段忽略（纯文本模式，不区分角色名/正文）
    """
    plain = lzss_decompress(orig_bytes)
    count, first_offsets, bc_start = parse_mes_header(plain)
    bc = plain[bc_start:]
    instrs = disassemble(bc)
    text_index = build_text_index(instrs)

    hit = miss = warn = 0

    for e in entries:
        eid = e.get('id', '')
        try:
            _, msg_s, ti_s = eid.rsplit('#', 2)
            msg_idx  = int(msg_s)
            text_idx = int(ti_s)
        except ValueError:
            miss += 1
            continue

        msg = e.get('message') or ''
        if not msg:
            continue

        slot = text_index.get((msg_idx, text_idx))
        if slot is None:
            warn += 1
            if warn <= 5:
                print(f"  [WARN] {filename_for_err}: no slot for id {eid}")
            continue

        try:
            set_text_string(slot, encode_text(msg))
            hit += 1
        except ValueError as exc:
            print(f"  [ERR] encode @ {eid}: {exc}")
            miss += 1

    if miss or warn > 0:
        print(f"  [{filename_for_err}] hit={hit} miss={miss} warn={warn}")

    new_bc, new_first = assemble(instrs, first_offsets)
    return pack_mes(count, new_bc, new_first)


# ───────────────────────────────────────────────
#  命令
# ───────────────────────────────────────────────

def _roundtrip_only(orig_bytes: bytes) -> bytes:
    plain = lzss_decompress(orig_bytes)
    count, first_offsets, bc_start = parse_mes_header(plain)
    instrs = disassemble(plain[bc_start:])
    new_bc, new_first = assemble(instrs, first_offsets)
    return pack_mes(count, new_bc, new_first)


def cmd_batch(orig_dir: str, json_dir: str, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    mes_files = sorted(glob.glob(os.path.join(orig_dir, '*.MES')))
    total = injected = 0
    for p in mes_files:
        fn = os.path.basename(p)
        json_path = os.path.join(json_dir, fn.replace('.MES', '.json'))
        orig = open(p, 'rb').read()
        if os.path.exists(json_path):
            entries = json.load(open(json_path, 'r', encoding='utf-8'))
            new_bytes = inject_one(orig, entries, fn)
            injected += 1
        else:
            new_bytes = _roundtrip_only(orig)
        open(os.path.join(out_dir, fn), 'wb').write(new_bytes)
        total += 1
    print(f"输出 {total} 个文件 -> {out_dir}，其中 {injected} 个注入了翻译")


def cmd_single(orig_path: str, json_path: str, out_path: str) -> None:
    fn = os.path.basename(orig_path)
    orig = open(orig_path, 'rb').read()
    entries = json.load(open(json_path, 'r', encoding='utf-8'))
    new_bytes = inject_one(orig, entries, fn)
    open(out_path, 'wb').write(new_bytes)
    print(f"{fn} 注入完成 -> {out_path}")


def cmd_verify(orig_dir: str) -> None:
    """纯 codec round-trip: 解压 -> 反汇编 -> 汇编 -> 压缩 -> 再解压 == 原 plain."""
    mes_files = sorted(glob.glob(os.path.join(orig_dir, '*.MES')))
    ok = fail = 0
    fail_names = []
    for p in mes_files:
        raw = open(p, 'rb').read()
        plain_orig = lzss_decompress(raw)
        new_file   = _roundtrip_only(raw)
        plain_new  = lzss_decompress(new_file)
        if plain_new == plain_orig:
            ok += 1
        else:
            fail += 1
            if len(fail_names) < 10:
                fail_names.append(os.path.basename(p))
    print(f"verify: {ok} OK / {fail} FAIL out of {len(mes_files)}")
    for n in fail_names:
        print(f"  FAIL: {n}")


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd = sys.argv[1].lower()
    if cmd == 'batch':
        if len(sys.argv) != 5:
            print("usage: batch <orig_mes_dir> <json_dir> <out_mes_dir>"); sys.exit(1)
        cmd_batch(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'single':
        if len(sys.argv) != 5:
            print("usage: single <orig.MES> <in.json> <out.MES>"); sys.exit(1)
        cmd_single(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'verify':
        if len(sys.argv) != 3:
            print("usage: verify <orig_mes_dir>"); sys.exit(1)
        cmd_verify(sys.argv[2])
    else:
        print(f"unknown cmd: {cmd}"); sys.exit(1)

if __name__ == '__main__':
    main()
