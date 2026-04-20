#!/usr/bin/env python3
"""
sct_inject.py - MSC/SCT 脚本文本注入工具 (v5)
引擎: NikuyokuH (MSC格式, HS engine)

批量模式: 同时处理 main.sct + scene.sct + at 文件
等长(默认): ##后0x20填充，不改偏移
变长(--varlen): 5层完整修正
  ① SCT场景表 offset/size
  ② at参数 场景内相对偏移
  ③ 场景内指针表
  ④ bytecode_offset
  ⑤ bytecode内跳转目标 (控制流追踪反汇编器)

用法:
  python sct_inject.py --main <orig_main.sct> <main.json> --scene <orig_scene.sct> <scene.json> --at <at_file> [--outdir DIR] [--encoding ENC] [--varlen]

  单文件也行:
  python sct_inject.py <orig.sct> <trans.json> [out.sct] [--at <at>] [--encoding ENC] [--varlen]
"""

import sys, os, json, struct


def parse_sct_layout(data):
    assert data[:4] == b'MSC\n'
    bytecode_size = struct.unpack_from('<H', data, 0x0A)[0]
    pos = 0x20
    type3_data_pos = type3_count = 0
    while pos + 8 <= len(data):
        ctype = struct.unpack_from('<I', data, pos)[0]
        ccount = struct.unpack_from('<I', data, pos + 4)[0]
        if ctype == 0:   pos += 8 + ccount * 37
        elif ctype == 1: pos += 8 + ccount * 48
        elif ctype == 3:
            type3_count = ccount; type3_data_pos = pos + 8
            pos += 8 + ccount * 35; break
        else: raise ValueError(f"Unknown chunk type {ctype}")
    bc_start = type3_data_pos + type3_count * 35
    scenes = []
    for i in range(type3_count):
        rec_off = type3_data_pos + i * 35
        name = data[rec_off:rec_off+17].split(b'\x00')[0].decode('ascii', errors='replace')
        scenes.append({
            'index': i, 'name': name, 'rec_off': rec_off,
            'file_offset': struct.unpack_from('<I', data, rec_off + 0x13)[0],
            'data_size': struct.unpack_from('<I', data, rec_off + 0x17)[0],
        })
    return {'bytecode_size': bytecode_size, 'type3_data_pos': type3_data_pos,
            'type3_count': type3_count, 'scenes': scenes,
            'scene_data_start': bc_start + bytecode_size}


def find_texts_in_blob(blob):
    segs = []
    i = 0
    while i < len(blob) - 1:
        if blob[i] == 0x23 and blob[i+1] == 0x23:
            s = i - 1
            while s > 0 and blob[s] != 0: s -= 1
            s += 1
            if s < i: segs.append((s, i+2))
            i += 2
        else: i += 1
    return segs


def inject_fixed(original_data, translations, target_encoding='cp932'):
    """等长注入: ##后0x20填充。"""
    result = bytearray(original_data)
    replaced = skipped = truncated = 0
    errors = []
    i = 0
    while i < len(result) - 1:
        if result[i] == 0x23 and result[i+1] == 0x23:
            s = i - 1
            while s > 0 and result[s] != 0: s -= 1
            s += 1
            if s < i:
                seg_id = f"sct_{s:06x}"
                orig_len = i + 2 - s
                if seg_id in translations:
                    new_text = translations[seg_id]
                    if not new_text.endswith('##'): new_text += '##'
                    try:
                        new_bytes = new_text.encode(target_encoding)
                    except UnicodeEncodeError as e:
                        errors.append(f"{seg_id}: {e}"); skipped += 1; i += 2; continue
                    if len(new_bytes) <= orig_len:
                        result[s:s+orig_len] = new_bytes + b'\x20' * (orig_len - len(new_bytes))
                        replaced += 1
                    else:
                        max_text_len = orig_len - 2
                        trunc = new_bytes[:max_text_len]
                        if len(trunc) > 0:
                            last = trunc[-1]
                            if (0x81 <= last <= 0x9F) or (0xE0 <= last <= 0xFC):
                                trunc = trunc[:-1]
                        trunc += b'##'
                        result[s:s+orig_len] = trunc + b'\x20' * (orig_len - len(trunc))
                        truncated += 1; replaced += 1
                else:
                    skipped += 1
            i += 2
        else: i += 1
    return bytes(result), replaced, skipped, truncated, errors


def _fix_bytecode_jumps(sc_data, new_bc_off, cum_delta, orig_bc_off, first_text_pos, deltas):
    """
    ⑤⑥ 修正 bytecode 区内的跳转目标和文本区操作数。
    
    ⑤ 跳转 (0x40/0x42): int32目标指向bytecode区，需 += cum_delta
    ⑥ 数据操作数: u32值指向文本区 [first_text, orig_bc_off)，需逐段delta修正
    """
    JUMP_MASKED = {0x40, 0x42}
    bc = sc_data[new_bc_off:]
    if len(bc) == 0:
        return 0, 0
    
    visited = set()
    queue = [0]
    jump_fixes = 0
    operand_fixes = 0
    
    def _adjust_text_ref(val):
        """对指向文本区的值应用逐段delta"""
        adj = 0
        for pos, cum_before, d in deltas:
            if val > pos: adj = cum_before + d
            else: break
        return val + adj if adj != 0 else val
    
    def _check_fix_operand(abs_offset, val):
        """检查并修正一个操作数值，如果它引用文本区"""
        nonlocal operand_fixes
        if val & 0x80000000:
            return  # 全局引用，不修正
        if first_text_pos <= val < orig_bc_off:
            new_val = _adjust_text_ref(val)
            if new_val != val:
                struct.pack_into('<I', sc_data, abs_offset, new_val)
                operand_fixes += 1
    
    while queue:
        pos = queue.pop()
        if pos in visited or pos < 0 or pos >= len(bc):
            continue
        visited.add(pos)
        
        op = bc[pos]
        om = op & 0xFE
        
        # ⑤ 跳转指令: 5字节, target += cum_delta
        if om in JUMP_MASKED:
            if pos + 5 > len(bc):
                continue
            target = struct.unpack_from('<i', sc_data, new_bc_off + pos + 1)[0]
            struct.pack_into('<i', sc_data, new_bc_off + pos + 1, target + cum_delta)
            jump_fixes += 1
            
            new_target_bc = target + cum_delta - new_bc_off
            if om == 0x42:
                queue.append(new_target_bc)
            else:
                queue.append(new_target_bc)
                queue.append(pos + 5)
            continue
        
        # 非跳转指令: 计算长度，检查操作数
        if om == 0xa0:
            # ⑥ 检查 0xa0 的参数 (pos+2处的u32)
            if pos + 6 <= len(bc):
                _check_fix_operand(new_bc_off + pos + 2,
                                   struct.unpack_from('<I', sc_data, new_bc_off + pos + 2)[0])
            size = 6
        elif op & 1:
            size = 3  # format A: 无u32操作数
        else:
            if pos + 2 > len(bc):
                continue
            flags = bc[pos + 1]
            if flags & 0x80 == 0:
                # format B: 10字节, u32 at +2 和 +6
                if pos + 10 <= len(bc):
                    _check_fix_operand(new_bc_off + pos + 2,
                                       struct.unpack_from('<I', sc_data, new_bc_off + pos + 2)[0])
                    _check_fix_operand(new_bc_off + pos + 6,
                                       struct.unpack_from('<I', sc_data, new_bc_off + pos + 6)[0])
                size = 10
            else:
                # format C: 6字节, u32 at +2
                if pos + 6 <= len(bc):
                    _check_fix_operand(new_bc_off + pos + 2,
                                       struct.unpack_from('<I', sc_data, new_bc_off + pos + 2)[0])
                size = 6
        
        queue.append(pos + size)
    
    return jump_fixes, operand_fixes


def inject_varlen(original_data, translations, target_encoding='cp932'):
    """变长注入。返回 (new_sct, scene_deltas, replaced, skipped, errors, bc_fixes)"""
    layout = parse_sct_layout(original_data)
    scenes = layout['scenes']
    prefix = bytearray(original_data[:layout['scene_data_start']])
    new_scene_blobs = []
    scene_deltas = []
    replaced = skipped = 0
    bc_fixes_total = 0
    op_fixes_total = 0
    errors = []

    for sc in scenes:
        sc_start = sc['file_offset']
        sc_data = bytearray(original_data[sc_start:sc_start + sc['data_size']])
        text_segs = find_texts_in_blob(sc_data)
        replacements = []
        for ls, le in text_segs:
            seg_id = f"sct_{sc_start + ls:06x}"
            if seg_id not in translations:
                skipped += 1; continue
            new_text = translations[seg_id]
            if not new_text.endswith('##'): new_text += '##'
            try:
                new_bytes = new_text.encode(target_encoding)
            except UnicodeEncodeError as e:
                errors.append(f"{seg_id}: {e}"); skipped += 1; continue
            replacements.append((ls, le, new_bytes))
            replaced += 1

        deltas = []
        cum_delta = 0
        replacements.sort(key=lambda x: x[0])
        for ls, le, nb in replacements:
            delta = len(nb) - (le - ls)
            if delta != 0:
                deltas.append((ls, cum_delta, delta))
                cum_delta += delta

        scene_deltas.append((deltas, cum_delta))

        # 读取原始 bc_off（替换前的值）
        orig_bc_off = struct.unpack_from('<I', sc_data, 1)[0]

        for ls, le, nb in reversed(replacements):
            sc_data[ls:le] = nb

        # 修正场景内指针表 + bytecode_offset + bytecode内跳转
        if cum_delta != 0 and len(sc_data) >= 5:
            # ④ 修正 bytecode_offset
            new_bc_off = orig_bc_off + cum_delta
            struct.pack_into('<I', sc_data, 1, new_bc_off)
            # ③ 修正场景内指针表（+5 到 orig_bc_off 的区域）
            #    只修正指向文本区的指针。文本区从第一个##文本段开始。
            #    指针表自身的索引/控制数据(小值)不动。
            first_text_pos = orig_bc_off  # default: no text area
            for _ls, _le in text_segs:
                if _ls < first_text_pos:
                    first_text_pos = _ls
                    break  # text_segs from find_texts_in_blob are in order
            j = 5
            ptr_fix_count = 0
            while j + 4 <= new_bc_off:
                pv = struct.unpack_from('<I', sc_data, j)[0]
                # 只修正指向文本区的指针（值 >= 原始第一个文本位置且 < bc_off）
                if first_text_pos <= pv < orig_bc_off:
                    adj = 0
                    for pos, cum_before, d in deltas:
                        if pv > pos: adj = cum_before + d
                        else: break
                    if adj != 0:
                        struct.pack_into('<I', sc_data, j, pv + adj)
                        ptr_fix_count += 1
                j += 4
            # ⑤⑥ 修正 bytecode 内跳转目标 + 文本区操作数
            bc_fix_count, op_fix_count = _fix_bytecode_jumps(
                sc_data, new_bc_off, cum_delta, orig_bc_off, first_text_pos, deltas)
            bc_fixes_total += bc_fix_count
            op_fixes_total += op_fix_count

        new_scene_blobs.append(bytes(sc_data))

    # 重建SCT
    result = bytearray(prefix)
    current_offset = layout['scene_data_start']
    for sc, blob in zip(scenes, new_scene_blobs):
        struct.pack_into('<I', result, sc['rec_off'] + 0x13, current_offset)
        struct.pack_into('<I', result, sc['rec_off'] + 0x17, len(blob))
        result.extend(blob)
        current_offset += len(blob)
    struct.pack_into('<I', result, 4, len(result))

    return bytes(result), scene_deltas, replaced, skipped, errors, bc_fixes_total, op_fixes_total


def fix_at(at_data, scene_deltas_list):
    """
    修正at文件。scene_deltas_list 是每个SCT对应的 scene_deltas。
    at只关联main.sct(230个场景),scene.sct有自己的场景但不关联at。
    
    AT参数的u32值是场景内绝对偏移，指向bytecode区（>= bc_off）。
    文本区变长后bytecode整体后移cum_delta，所以AT参数直接 += cum_delta。
    """
    new_at = bytearray(at_data)
    at_count = struct.unpack_from('<I', at_data, 0)[0]
    at_fixed = 0

    for scene_deltas in scene_deltas_list:
        if len(scene_deltas) != at_count:
            continue  # 只处理条目数匹配的(main.sct)
        for sc_idx, (deltas, cum_delta) in enumerate(scene_deltas):
            if cum_delta == 0: continue
            if sc_idx >= at_count: continue
            aoff = 8 + sc_idx * 25
            n_params = struct.unpack_from('<I', new_at, aoff + 17)[0]
            data_off = struct.unpack_from('<I', new_at, aoff + 21)[0]
            for j in range(n_params):
                poff = data_off + j * 5
                if poff + 5 > len(new_at): continue
                old_val = struct.unpack_from('<I', new_at, poff)[0]
                if old_val > 0:
                    struct.pack_into('<I', new_at, poff, old_val + cum_delta)
                    at_fixed += 1

    return bytes(new_at), at_fixed


def find_text_segments(data):
    segs = []
    i = 0
    while i < len(data) - 1:
        if data[i] == 0x23 and data[i+1] == 0x23:
            s = i - 1
            while s > 0 and data[s] != 0: s -= 1
            s += 1
            if s < i: segs.append((s, i+2))
            i += 2
        else: i += 1
    return segs


def verify_sct(label, original_data, new_data):
    print(f"[{label}] 文本段: {len(find_text_segments(original_data))} → {len(find_text_segments(new_data))}")
    new_layout = parse_sct_layout(new_data)
    ok = True
    for j in range(len(new_layout['scenes'])-1):
        s1, s2 = new_layout['scenes'][j], new_layout['scenes'][j+1]
        if s1['file_offset']+s1['data_size'] != s2['file_offset']:
            print(f"  [警告] 场景{j}→{j+1}偏移不连续!"); ok = False
    last = new_layout['scenes'][-1]
    if last['file_offset']+last['data_size'] != len(new_data):
        print(f"  [警告] 最后场景end≠filesize!"); ok = False
    if ok: print(f"  场景表连续性 ✓")
    # 验证bytecode跳转目标有效性
    bc_ok = True
    jump_count = 0
    for sc in new_layout['scenes']:
        sc_data = new_data[sc['file_offset']:sc['file_offset']+sc['data_size']]
        if len(sc_data) < 5 or sc_data[0] != 0x40:
            continue
        bc_off = struct.unpack_from('<I', sc_data, 1)[0]
        if bc_off >= len(sc_data):
            continue
        bc = sc_data[bc_off:]
        # 控制流追踪验证
        visited = set()
        queue = [0]
        while queue:
            pos = queue.pop()
            if pos in visited or pos < 0 or pos >= len(bc): continue
            visited.add(pos)
            op = bc[pos]
            om = op & 0xFE
            if om in (0x40, 0x42):
                if pos + 5 <= len(bc):
                    target = struct.unpack_from('<i', bc, pos + 1)[0]
                    jump_count += 1
                    if target < bc_off or target >= len(sc_data):
                        print(f"  [警告] 场景{sc['name']} BC跳转目标越界: {target:#x}")
                        bc_ok = False
                    tbc = target - bc_off
                    if om == 0x42:
                        queue.append(tbc)
                    else:
                        queue.append(tbc)
                        queue.append(pos + 5)
                continue
            if om == 0xa0: size = 6
            elif op & 1: size = 3
            elif pos + 2 <= len(bc) and bc[pos+1] & 0x80 == 0: size = 10
            elif pos + 2 <= len(bc): size = 6
            else: continue
            queue.append(pos + size)
    if bc_ok:
        print(f"  BC跳转有效性 ✓ ({jump_count}个)")


def process_one(label, orig_path, json_path, out_path, varlen, encoding, collect_deltas=None):
    """处理单个SCT文件。collect_deltas: 列表，变长时追加scene_deltas。"""
    with open(orig_path, 'rb') as f: orig = f.read()
    with open(json_path, 'r', encoding='utf-8') as f: entries = json.load(f)
    translations = {e['id']: e['message'] for e in entries if e.get('id') and e.get('message')}

    layout = parse_sct_layout(orig)
    print(f"[{label}] 原始={len(orig)}B 翻译={len(translations)}条 场景={layout['type3_count']}")

    if varlen:
        new_data, scene_deltas, replaced, skipped, errors, bc_fixes, op_fixes = inject_varlen(orig, translations, encoding)
        if collect_deltas is not None:
            collect_deltas.append(scene_deltas)
        diff = len(new_data) - len(orig)
        print(f"  替换={replaced} 保留={skipped} 错误={len(errors)} BC跳转={bc_fixes} BC操作数={op_fixes} 大小{'+' if diff>=0 else ''}{diff}")
        verify_sct(label, orig, new_data)
    else:
        new_data, replaced, skipped, truncated, errors = inject_fixed(orig, translations, encoding)
        print(f"  替换={replaced} 保留={skipped} 截断={truncated} 错误={len(errors)} 大小不变")

    for e in errors[:5]: print(f"  {e}")
    with open(out_path, 'wb') as f: f.write(new_data)
    print(f"  → {out_path}")
    return new_data


def main():
    # 解析参数
    args = sys.argv[1:]
    main_sct = main_json = scene_sct = scene_json = at_path = outdir = None
    encoding = 'cp932'
    varlen = False
    single_sct = single_json = single_out = None

    i = 0
    while i < len(args):
        a = args[i]
        if a == '--main' and i+2 < len(args):
            main_sct, main_json = args[i+1], args[i+2]; i += 3
        elif a == '--scene' and i+2 < len(args):
            scene_sct, scene_json = args[i+1], args[i+2]; i += 3
        elif a == '--at' and i+1 < len(args):
            at_path = args[i+1]; i += 2
        elif a == '--outdir' and i+1 < len(args):
            outdir = args[i+1]; i += 2
        elif a == '--encoding' and i+1 < len(args):
            encoding = args[i+1]; i += 2
        elif a == '--varlen':
            varlen = True; i += 1
        elif single_sct is None:
            single_sct = a; i += 1
        elif single_json is None:
            single_json = a; i += 1
        elif single_out is None:
            single_out = a; i += 1
        else: i += 1

    # 批量模式
    if main_sct and scene_sct:
        if not outdir: outdir = '.'
        os.makedirs(outdir, exist_ok=True)
        print(f"[模式] 批量{'变长' if varlen else '等长'}  编码={encoding}  输出={outdir}")

        all_deltas = []
        process_one("main", main_sct, main_json,
                     os.path.join(outdir, 'main.sct'), varlen, encoding,
                     all_deltas if varlen else None)
        process_one("scene", scene_sct, scene_json,
                     os.path.join(outdir, 'scene.sct'), varlen, encoding,
                     all_deltas if varlen else None)

        if at_path and varlen and all_deltas:
            with open(at_path, 'rb') as f: at_data = f.read()
            new_at, at_fixed = fix_at(at_data, all_deltas)
            at_out = os.path.join(outdir, 'at')
            with open(at_out, 'wb') as f: f.write(new_at)
            print(f"[at] {at_fixed}个参数修正 → {at_out}")
        elif at_path and not varlen:
            # 等长模式at不变，直接复制
            import shutil
            at_out = os.path.join(outdir, 'at')
            shutil.copy2(at_path, at_out)
            print(f"[at] 等长模式无需修改 → {at_out}")

        print("[完成] 将输出目录下的 main.sct, scene.sct, at 复制到游戏目录即可")
        return

    # 单文件模式
    if not single_sct or not single_json:
        print("用法(批量):")
        print(f"  {sys.argv[0]} --main <main.sct> <main.json> --scene <scene.sct> <scene.json> --at <at> [--outdir DIR] [--encoding ENC] [--varlen]")
        print()
        print("用法(单文件):")
        print(f"  {sys.argv[0]} <orig.sct> <trans.json> [out.sct] [--at <at>] [--encoding ENC] [--varlen]")
        sys.exit(1)

    if not single_out:
        single_out = os.path.splitext(single_sct)[0] + '_injected.sct'

    print(f"[模式] 单文件{'变长' if varlen else '等长'}  编码={encoding}")
    all_deltas = []
    process_one("sct", single_sct, single_json, single_out, varlen, encoding,
                all_deltas if varlen else None)

    if at_path and varlen and all_deltas:
        with open(at_path, 'rb') as f: at_data = f.read()
        new_at, at_fixed = fix_at(at_data, all_deltas)
        at_out = os.path.join(os.path.dirname(single_out) or '.', 'at_patched')
        with open(at_out, 'wb') as f: f.write(new_at)
        print(f"[at] {at_fixed}个参数修正 → {at_out}")


if __name__ == '__main__':
    main()
