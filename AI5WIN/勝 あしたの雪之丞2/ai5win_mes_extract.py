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


def _scan_flag_4035_states(ops_by_id_list, dec):
    """按顺序扫所有块, 追踪 B_FLAG id=4035 (对话框模式) 的当前值.
    返回 [value_at_block_entry, ...] 与 ops_by_id_list 等长.
    value=12 → no_name_label 模式 (独白); 其它/None → 正常显示.
    """
    cur = None
    states = []
    for ops in ops_by_id_list:
        states.append(cur)   # 进入本块时的状态
        # 扫本块内是否重设 4035
        for (off, op, args, _) in ops:
            if op != 0x03:
                continue
            id_val = None
            first_expr_range = None
            for a in args:
                if a[0] == 'ID16':
                    id_val = int.from_bytes(a[3], 'little')
                elif a[0] == 'EXPRS' and a[3]:
                    first_expr_range = a[3][0]
            if id_val == 4035 and first_expr_range:
                es, el = first_expr_range
                expr_bytes = bytes(dec[es:es+el])
                # 格式: 'NN ff' 单字节 push, 或 'f1 LO HI ff' u16 push
                if len(expr_bytes) >= 2 and expr_bytes[-1] == 0xFF:
                    body = expr_bytes[:-1]
                    if len(body) == 1 and body[0] < 0x80:
                        cur = body[0]
                    elif len(body) == 3 and body[0] == 0xF1:
                        cur = int.from_bytes(body[1:3], 'little')
    return states


def _collect_block(block_ops, dec=None):
    """从块内 ops 抓文本.
    返回 (name, message, choices, chapter_title, no_name_label)

    dec: 可选, 原始解压字节. 若提供则会精确检测 B_FLAG id=4035 的值
         (判断游戏是否在"独白模式"下不显示 name).

    识别规则:
      - "选择支 TEXT" (choices):
          CH_POS (op 0x0e) 后紧跟的 TEXT (op 0x01). 例: '●水島を刺激する...'
      - "章节标题" (chapter_title):
          独立的 MENU_SET (op 0x10) 里的合法 STR slot (过滤含 \\n 的名前标签).
      - "名前 + 台词":
          块首 TEXT 后紧跟 0x11 INTERRUPT: 首 TEXT=name, 下一个非选择支 TEXT=message.
          否则块首 TEXT 就是 message.
      - "no_name_label":
          块内 B_FLAG_SET id=4035 value=12 (0x0C) -- 游戏切到"独白模式"
          对话框里不显示角色名 (即使 bytecode 有 name TEXT).
          (仅当 dec != None 时检测.)
    """
    name = None
    message = None
    choices = []
    chapter_title = None
    no_name_label = False

    ops = list(block_ops)

    # 标记 CH_POS 后紧跟的 TEXT (选择支文本)
    # 按物理顺序记录: 哪些 TEXT op index 是 "CH_POS 紧跟的选择支"
    # 必须保序 (用 list 而非 set), 否则 choice_idx 和物理选项顺序对应错乱
    is_choice_text = []
    for i, (off, op, _, _) in enumerate(ops):
        if op == 0x0e and i + 1 < len(ops) and ops[i + 1][1] == 0x01:
            is_choice_text.append(i + 1)
    is_choice_text_set = set(is_choice_text)   # 用于 O(1) 查找

    # 1. 选择支 TEXT (按物理顺序 = CH_POS 出现顺序)
    for i in is_choice_text:
        for (typ, ps, sz, val) in ops[i][2]:
            if typ == 'TEXT' and _is_user_text(val):
                try:
                    s = val.decode('cp932')
                    choices.append(s)
                except:
                    pass
                break

    # 2. 名前 + 台词 (跳过 choice_text)
    text_entries = []
    for i, (off, op, args, _) in enumerate(ops):
        if op != 0x01 or i in is_choice_text_set:
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

    # 3. 章节标题 (过滤含 \\n 的名前标签)
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
                    continue   # 过滤名前立绘标签
                try:
                    chapter_title = sl[3].decode('cp932')
                except:
                    pass

    # 4. no_name_label: B_FLAG_SET id=4035 value=12 (0x0C)
    if dec is not None:
        for (off, op, args, _) in ops:
            if op != 0x03:
                continue
            id_val = None
            first_expr_range = None
            for a in args:
                if a[0] == 'ID16':
                    id_val = int.from_bytes(a[3], 'little')
                elif a[0] == 'EXPRS' and a[3]:
                    first_expr_range = a[3][0]   # (start, len)
            if id_val == 4035 and first_expr_range:
                es, el = first_expr_range
                expr_bytes = bytes(dec[es:es+el])
                # 最小 expr: 单字节 push (如 '0c ff') 或 'f1 XX XX ff' (push u16)
                # 判定 value==12: 字节序列是 `0c ff`
                if expr_bytes == b'\x0c\xff':
                    no_name_label = True
                    break

    return name, message, choices, chapter_title, no_name_label


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

    # 全局追踪 B_FLAG 4035 (对话框模式) 状态
    # 顺序: [prelude, id=0, id=1, ..., id=mc-1]
    all_block_ops = [prelude_ops] + ops_by_id
    flag_states = _scan_flag_4035_states(all_block_ops, dec)
    # 块入口状态 -> no_name_label (12 是独白模式)
    # 但 _collect_block 只看本块是否重设, 如果本块重设了就应该用重设后的值
    # 所以真正判据: "本块离开时状态 == 12" → no_name_label
    # 更精确地: "在本块的消息显示时, 4035 是否为 12"?
    # 保守做法: 块入口状态 OR 本块内任何消息显示前的重设值
    # 简单: 块出口状态 (最接近消息实际生效时的值)
    # flag_states 给的是入口状态; 出口状态 = 下一个块的入口状态
    def exit_state(idx):
        if idx + 1 < len(flag_states):
            return flag_states[idx + 1]
        # 最后一块: 再扫一遍本块得最终值
        cur = flag_states[idx]
        for (off, op, args, _) in all_block_ops[idx]:
            if op != 0x03: continue
            id_val = None; er = None
            for a in args:
                if a[0] == 'ID16': id_val = int.from_bytes(a[3], 'little')
                elif a[0] == 'EXPRS' and a[3]: er = a[3][0]
            if id_val == 4035 and er:
                eb = bytes(dec[er[0]:er[0]+er[1]])
                if len(eb) >= 2 and eb[-1] == 0xFF:
                    body = eb[:-1]
                    if len(body) == 1 and body[0] < 0x80: cur = body[0]
                    elif len(body) == 3 and body[0] == 0xF1:
                        cur = int.from_bytes(body[1:3], 'little')
        return cur

    entries = []

    def emit_block(list_idx, block_id, ops):
        """把一个块的 name/message/choices/chapter_title 全部展开为独立 entry"""
        nm, msg, chs, ct, _no_label = _collect_block(ops, dec)
        # 用全局状态判 no_name_label (考虑跨块继承)
        state = exit_state(list_idx)
        no_label = (state == 12)
        # 1. 正文台词
        if nm or msg:
            ent = {"id": block_id, "name": nm or "", "message": msg or ""}
            if nm and no_label:
                ent["no_name_label"] = True
            entries.append(ent)
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

    # 前导区: list_idx=0, block_id=-1
    if prelude_ops:
        emit_block(0, -1, prelude_ops)

    for i in range(mc):
        emit_block(i + 1, i, ops_by_id[i])

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
