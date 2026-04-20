#!/usr/bin/env python3
"""AI5WIN v2 MES 文本提取工具 v4 (あしたの雪之丞2)
基于 ai5win_disasm 精确反汇编器.

抓取策略 (以 id=msg 块为单位):
  1. 双字节 TEXT 指令 (op 0x01) 全角文本: 首条如有 0x11 INTERRUPT 紧跟视为名前
  2. CH_POS (op 0x0e) / MENU_SET (op 0x10) / MENU (op 0x15) 的 slot_list 里
     以 cp932 全角开头的 STR slot 视为可翻译菜单项 (选择支/按钮文本)

输出 JSON (GalTransl 兼容):
  [{id, name, message, menu_items?}]

用法:
  python ai5win_mes_extract.py <input.mes>   [output.json]
  python ai5win_mes_extract.py <mes_dir>     [output_dir]   (批量)
"""

import struct, json, sys, os
from ai5win_disasm import lzss_decompress, parse_mes


_RES_EXTS = (b'.g24', b'.msk', b'.ogg', b'.wav', b'.bmp', b'.png',
             b'.mes', b'.ea6', b'.ea5', b'.eav', b'.ttf', b'.fnt')


def _is_user_text(raw):
    """判断 cp932 字节是否可翻译 (非文件名/非纯ASCII参数)."""
    if len(raw) < 2:
        return False
    raw_lower = raw.lower()
    for ext in _RES_EXTS:
        if ext in raw_lower:
            return False
    if not any(0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEF for b in raw):
        return False
    for b in raw:
        if b < 0x20 and b != 0x0A:
            return False
    try:
        raw.decode('cp932')
        return True
    except:
        return False


def _collect_block(block_ops):
    """从块内 ops 抓文本. 返回 (name, message, choices, chapter_title)

    识别规则:
      - "选择支 TEXT" (choices):
          CH_POS (op 0x0e) 后紧跟的 TEXT (op 0x01). 例: '●水島を刺激する...'
      - "章节标题" (chapter_title):
          独立的 MENU_SET (op 0x10) 里的合法 STR slot.
          (这通常是本块 / 本段剧情的显示标题,
           例: '屋上で昼食', 'フェンスの向こう側')
      - "名前 + 台词":
          块首 TEXT 后紧跟 0x11 INTERRUPT: 首 TEXT=name, 下一个非选择支 TEXT=message.
          否则块首 TEXT 就是 message.
    """
    name = None
    message = None
    choices = []
    chapter_title = None

    ops = list(block_ops)

    # 标记 CH_POS 后紧跟的 TEXT (选择支文本)
    is_choice_text = set()
    for i, (off, op, _, _) in enumerate(ops):
        if op == 0x0e and i + 1 < len(ops) and ops[i + 1][1] == 0x01:
            is_choice_text.add(i + 1)

    # 1. 选择支 TEXT
    for i in is_choice_text:
        for (typ, ps, sz, val) in ops[i][2]:
            if typ == 'TEXT' and _is_user_text(val):
                try:
                    s = val.decode('cp932')
                    if s not in choices:
                        choices.append(s)
                except:
                    pass
                break

    # 2. 名前 + 台词 (跳过 choice_text)
    text_entries = []
    for i, (off, op, args, _) in enumerate(ops):
        if op != 0x01 or i in is_choice_text:
            continue
        for (typ, ps, sz, val) in args:
            if typ == 'TEXT' and _is_user_text(val):
                try:
                    text_entries.append((i, val.decode('cp932')))
                except:
                    pass
                break

    if text_entries:
        first_idx, first_text = text_entries[0]
        has_name_marker = (first_idx + 1 < len(ops)
                           and ops[first_idx + 1][1] == 0x11)
        if has_name_marker and len(text_entries) >= 2:
            name = first_text
            message = text_entries[1][1]
        elif has_name_marker:
            name = first_text
        else:
            message = first_text

    # 3. 章节标题: MENU_SET 里最后出现的合法 STR (通常只有一条)
    #    过滤掉含 '\n' (0x5C 0x6E) 的 — 那是名前立绘标签 (如 '晶子\n', 'あきら\n'), 不是真章节标题.
    for (off, op, args, _) in ops:
        if op != 0x10:
            continue
        for (typ, ps, sz, val) in args:
            if typ != 'SLOTS':
                continue
            for sl in val:
                if sl[0] != 'STR':
                    continue
                if not _is_user_text(sl[3]):
                    continue
                if b'\\n' in sl[3]:
                    continue   # 过滤名前标签
                try:
                    chapter_title = sl[3].decode('cp932')
                except:
                    pass

    return name, message, choices, chapter_title


def extract_file(mes_path, json_path, verbose=True):
    compressed = open(mes_path, 'rb').read()
    try:
        dec = lzss_decompress(compressed)
    except Exception as e:
        if verbose:
            print(f"  {os.path.basename(mes_path)}: LZSS 解压失败: {e}")
        return 0

    if len(dec) < 4:
        if verbose:
            print(f"  {os.path.basename(mes_path)}: 空文件")
        return 0

    mc, hs, msg_rel, msg_abs, lines = parse_mes(dec)
    if mc == 0:
        if verbose:
            print(f"  {os.path.basename(mes_path)}: mc=0, 跳过")
        return 0

    # 按 id 分组 ops. 前导区 [hs, ma[0]) 归 id=-1 (序章/文件初始化段)
    prelude_ops = []
    ops_by_id = [[] for _ in range(mc)]
    id_idx = 0
    for item in lines:
        off = item[0]
        if off < msg_abs[0]:
            prelude_ops.append(item)
            continue
        while id_idx + 1 < mc and off >= msg_abs[id_idx + 1]:
            id_idx += 1
        ops_by_id[id_idx].append(item)

    entries = []

    def emit_block(block_id, ops):
        """把一个块的 name/message/choices/chapter_title 全部展开为独立 entry"""
        nm, msg, chs, ct = _collect_block(ops)
        # 1. 正文台词
        if nm or msg:
            entries.append({"id": block_id, "name": nm or "", "message": msg or ""})
        # 2. 每个选择支作为独立 entry
        for idx, c in enumerate(chs):
            entries.append({
                "id": block_id, "name": "", "message": c,
                "is_choice": True, "choice_idx": idx,
            })
        # 3. 章节标题作为独立 entry
        if ct:
            entries.append({
                "id": block_id, "name": "", "message": ct,
                "is_chapter_title": True,
            })

    # 前导区
    if prelude_ops:
        emit_block(-1, prelude_ops)

    for i in range(mc):
        emit_block(i, ops_by_id[i])

    if not entries:
        if verbose:
            print(f"  {os.path.basename(mes_path)}: 无文本")
        return 0

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    nmsg = sum(1 for e in entries if not e.get("is_choice") and not e.get("is_chapter_title"))
    nchoice = sum(1 for e in entries if e.get("is_choice"))
    nchap = sum(1 for e in entries if e.get("is_chapter_title"))
    if verbose:
        print(f"  {os.path.basename(mes_path)}: "
              f"{len(compressed)}→{len(dec)}B, "
              f"{len(entries)} entries ({nmsg} msg, {nchoice} choices, {nchap} titles)")
    return len(entries)


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    src = sys.argv[1]
    if os.path.isdir(src):
        out = sys.argv[2] if len(sys.argv) > 2 else src + '_json'
        os.makedirs(out, exist_ok=True)
        files = sorted(f for f in os.listdir(src)
                       if f.upper().endswith('.MES') and not f.startswith('_'))
        total = 0
        for fn in files:
            jp = os.path.join(out, os.path.splitext(fn)[0] + '.json')
            total += extract_file(os.path.join(src, fn), jp)
        print(f"[完成] {len(files)} 文件, {total} entries")
    else:
        jp = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + '.json'
        extract_file(src, jp)


if __name__ == '__main__':
    main()
