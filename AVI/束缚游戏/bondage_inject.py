#!/usr/bin/env python3
"""BONDAGE 引擎文本注入器 - 变长文本重注入

策略:
1. 重建文本池: 按 text_off 排序, 依次铺新文本 (保留未翻译条目原文)
2. 建立 old_off -> new_off 映射
3. 扫描 bc 区所有文本引用点 (通过同一张 OP 表), 用映射修补 u16
4. 更新 header 中的 text_rel (如文本池相对 bc 位置变化)
5. 不改动 index 表 (label bc 偏移保持不变)
6. 不改动 bc 区长度 (文本池追加在原位置之后, bc 区原位保留)

关键假设:
- bc 区不变, 只改 u16 文本偏移值
- 文本池用 \0 终止, 2 字节对齐
- text_rel 是 u16, 文本池起点必须在 bc_base + 64KB 内 (此处等于 bc_size)
"""
import struct, sys, json, os
from bondage_ops import MAIN_OPS, SUB_OPS, parse_header, parse_labels


def encode_text(s: str) -> bytes:
    """CP932 编码 + \\0 终止 + 2 字节对齐"""
    b = s.encode('cp932', errors='replace') + b'\x00'
    if len(b) & 1: b += b'\x00'
    return b


def collect_text_refs(data: bytes, hdr: dict, labels: dict) -> dict:
    """扫描 bc 区所有文本 u16 引用, 返回 {text_off: [(pc_of_u16, ref_type), ...]}
    ref_type: 'text' 或 'name_text'
    """
    refs = {}

    def record(text_off, pc, ref_type):
        refs.setdefault(text_off, []).append((pc, ref_type))

    # 复用提取器的扫描逻辑, 但记录的是 u16 自身的 pc
    class RefWalker:
        def __init__(self):
            self.pc = 0
        def u8(self):
            v = data[hdr['bc_base'] + self.pc]; self.pc += 1; return v
        def u16_at(self):
            """读 u16, 返回 (值, u16的pc)"""
            pc_of_u16 = self.pc
            v = struct.unpack_from('<H', data, hdr['bc_base'] + self.pc)[0]
            self.pc += 2
            return v, pc_of_u16
        def u16(self): return self.u16_at()[0]
        def consume_flag(self): self.pc += 3
        def consume_expr(self):
            while self.pc < hdr['bc_size']:
                if self.u8() == 0xFF: return
        def consume_switch(self):
            self.u8(); self.u16(); self.u16()
            n = self.u8()
            for _ in range(n): self.consume_flag()

    w = RefWalker()

    def consume_with_refs(fields):
        for ftype, count in fields:
            for _ in range(count):
                if   ftype == 'u8':    w.u8()
                elif ftype == 'u16':   w.u16()
                elif ftype == 'flag':  w.consume_flag()
                elif ftype == 'expr':  w.consume_expr()
                elif ftype == 'switch_table': w.consume_switch()
                elif ftype in ('text', 'name_text'):
                    v, pc_u16 = w.u16_at()
                    record(v, pc_u16, ftype)

    def scan(start_pc, visited_global):
        w.pc = start_pc
        visited = set()
        while w.pc < hdr['bc_size'] and w.pc not in visited:
            visited.add(w.pc); visited_global.add(w.pc)
            op = w.u8()
            if op not in MAIN_OPS: return
            _, fields, flow = MAIN_OPS[op]
            if fields == 'dispatch_sub':
                sub = w.u8()
                if sub not in SUB_OPS: return
                try: consume_with_refs(SUB_OPS[sub][1])
                except (IndexError, struct.error): return
            else:
                try: consume_with_refs(fields)
                except (IndexError, struct.error): return
                if flow == 'end': return

    global_visited = set()
    for lid in sorted(labels):
        scan(labels[lid], global_visited)
    return refs


def inject(bin_path: str, json_path: str, out_path: str,
           name_table_path: str = None, mode: str = 'varlen',
           fix_path: str = None) -> list:
    """注入
    mode: 'varlen' (变长, 重建文本池并修补引用) 或 'fixed' (等长, 原槽位覆盖)
    fix_path: 若非 None, 把等长模式下被截断的条目写到此 JSON; 默认与 out_path 同目录
    返回: fix 记录列表 (每条包含 text_off/原文/译文/原空间/译文空间/溢出字节数/配对信息)
    """
    assert mode in ('varlen', 'fixed'), f"mode 必须是 varlen 或 fixed, 收到 {mode!r}"
    data = bytearray(open(bin_path, 'rb').read())
    hdr = parse_header(bytes(data))
    labels = parse_labels(bytes(data), hdr)
    entries = json.load(open(json_path, encoding='utf-8'))

    # 加载 name 表 (可选): {原 name: {translation: 译名}}
    name_map = {}
    if name_table_path is None:
        # 自动查找同名 _names.json
        guess = os.path.splitext(json_path)[0] + '_names.json'
        if os.path.exists(guess): name_table_path = guess
    if name_table_path and os.path.exists(name_table_path):
        nt = json.load(open(name_table_path, encoding='utf-8'))
        for k, v in nt.items():
            name_map[k] = v.get('translation', k) if isinstance(v, dict) else v
        print(f"[name] 加载 {len(name_map)} 个说话人映射")

    # 1. 扫描所有文本引用点
    refs = collect_text_refs(bytes(data), hdr, labels)
    print(f"[1/4] 扫描到 {len(refs)} 个唯一 text_off, "
          f"共 {sum(len(v) for v in refs.values())} 处引用")

    # 2. 建立 old_off -> 翻译文本 映射 (未翻译的保留原文)
    translations = {}
    for e in entries:
        # 主消息
        translations[e['text_off']] = e.get('message', e.get('src_msg', ''))
        # 若带 name, 回填 name 原位置 (使用 name_map 翻译, 加回 【】 外壳)
        if e.get('name') and e.get('name_text_off') is not None:
            orig_name = e['name']
            translated = name_map.get(orig_name, orig_name)
            translations[e['name_text_off']] = '【' + translated + '】' 

    # 3. 收集文本池所有原始字符串 (包括未被引用的, 保留完整池)
    # 扫描文本池里所有 null-terminated cstring 起点
    orig_offs = []
    i = hdr['text_base']
    while i < len(data):
        j = i
        while j < len(data) and data[j] != 0: j += 1
        rel = i - hdr['text_base']
        if j > i: orig_offs.append(rel)
        while j < len(data) and data[j] == 0: j += 1
        i = j
    print(f"[2/4] 文本池原始 cstring: {len(orig_offs)} 条")

    # 建立 name↔text_off 反查 (用于 fix 记录里显示谁被截断)
    name_for_off = {}
    for e in entries:
        if e.get('name'):
            name_for_off[e['text_off']] = e['name']

    # 计算每个 old_off 的 "可用空间" (从该 off 到下一个 cstring 起点, 含 \0)
    slot_size = {}
    for idx, off in enumerate(orig_offs):
        if idx + 1 < len(orig_offs):
            slot_size[off] = orig_offs[idx+1] - off
        else:
            slot_size[off] = (len(data) - hdr['text_base']) - off

    fix_records = []  # 截断溢出记录

    if mode == 'fixed':
        # ========== 等长模式 ==========
        # 文本池原样保留, 直接在原位置覆盖; 超长截断并记录
        new_pool = bytearray(data[hdr['text_base']:])  # 复制原池
        for old_off in orig_offs:
            if old_off not in translations: continue
            orig_start = old_off
            orig_end   = new_pool.index(0, orig_start)
            orig_bytes = new_pool[orig_start:orig_end]
            orig_str   = orig_bytes.decode('cp932', errors='replace')
            new_str    = translations[old_off]
            if new_str == orig_str: continue  # 未翻译

            encoded = new_str.encode('cp932', errors='replace')
            avail   = slot_size[old_off] - 1  # 减 1 留给 \0 终止符
            overflow = len(encoded) - avail

            if overflow > 0:
                # 截断: 保留能塞下的部分, 注意 CP932 双字节不能从中间截断
                truncated = encoded[:avail]
                # 修复 CP932 双字节截断: 逐字节扫描, 如果最后 1 字节是 leadbyte 就砍掉
                fixed = bytearray()
                i = 0
                while i < len(truncated):
                    b = truncated[i]
                    if (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC):
                        if i + 1 >= len(truncated): break  # 尾巴上的单独 leadbyte, 丢弃
                        fixed.append(b); fixed.append(truncated[i+1]); i += 2
                    else:
                        fixed.append(b); i += 1
                # 回写: fixed + 0 + padding 填满原槽位
                new_pool[orig_start:orig_start+slot_size[old_off]] = (
                    bytes(fixed) + b'\x00' * (slot_size[old_off] - len(fixed))
                )
                fix_records.append({
                    'text_off': old_off,
                    'name': name_for_off.get(old_off, ''),
                    'orig_bytes': len(orig_bytes),
                    'slot_size': slot_size[old_off],
                    'trans_bytes': len(encoded),
                    'overflow': overflow,
                    'orig_text': orig_str,
                    'trans_text': new_str,
                    'truncated_text': fixed.decode('cp932', errors='replace'),
                })
            else:
                # 塞得下: encoded + \0 + padding 填满槽位保证偏移不变
                new_pool[orig_start:orig_start+slot_size[old_off]] = (
                    encoded + b'\x00' * (slot_size[old_off] - len(encoded))
                )

        new_file = bytearray(data[:hdr['text_base']])
        new_file.extend(new_pool)
        with open(out_path, 'wb') as f: f.write(new_file)
        print(f"[3/3] 等长注入 → {out_path}")
        print(f"      原文件: {len(data)} B → 新文件: {len(new_file)} B  (应一致)")
        print(f"      截断条目: {len(fix_records)} 条"
              + (f" (总溢出 {sum(r['overflow'] for r in fix_records)} B)"
                 if fix_records else ""))

    else:
        # ========== 变长模式 (原逻辑) ==========
        # 4. 重建文本池
        new_pool = bytearray()
        off_map = {}
        for old_off in orig_offs:
            start = hdr['text_base'] + old_off
            end = data.index(0, start)
            orig_str = data[start:end].decode('cp932', errors='replace')
            new_str = translations.get(old_off, orig_str)
            encoded = encode_text(new_str)
            off_map[old_off] = len(new_pool)
            new_pool.extend(encoded)
        print(f"[3/4] 文本池重建: {len(data)-hdr['text_base']} B → {len(new_pool)} B")

        # 5. 修补 bc 区所有 u16 引用
        patch_count = 0
        for old_off, locations in refs.items():
            if old_off not in off_map:
                print(f"  [warn] 引用 off={old_off:#x} 不在 cstring 表中, 跳过")
                continue
            new_off = off_map[old_off]
            for pc_u16, _ in locations:
                struct.pack_into('<H', data, hdr['bc_base'] + pc_u16, new_off)
                patch_count += 1

        # 6. 重建文件
        new_file = bytearray(data[:hdr['text_base']])
        new_file.extend(new_pool)
        with open(out_path, 'wb') as f: f.write(new_file)
        print(f"[4/4] 修补 {patch_count} 处 u16 → {out_path}")
        print(f"      原文件: {len(data)} B → 新文件: {len(new_file)} B")

    # 输出 fix.json (仅等长模式且有截断时)
    if fix_records:
        if fix_path is None:
            stem = os.path.splitext(os.path.basename(out_path))[0]
            fix_path = os.path.join(os.path.dirname(out_path) or '.',
                                    stem + '_fix.json')
        with open(fix_path, 'w', encoding='utf-8') as f:
            json.dump(fix_records, f, ensure_ascii=False, indent=2)
        print(f"      ⚠ 截断记录 → {fix_path}")

    return fix_records


def roundtrip_test(bin_path: str):
    """Round-trip 测试: 提取 -> 原样回注 -> 对比"""
    import bondage_extract as be
    print("=" * 50)
    print("Round-trip 测试")
    print("=" * 50)
    result = be.extract(bin_path)
    json_data = []
    for e in result['entries']:
        item = {'text_off': e['text_off'], 'message': e['message']}
        if e.get('name'):
            item['name'] = e['name']
            item['name_text_off'] = e['name_text_off']
        json_data.append(item)
    tmp_json = '/tmp/rt.json'
    tmp_bin = '/tmp/rt.bin'
    with open(tmp_json, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, ensure_ascii=False)
    inject(bin_path, tmp_json, tmp_bin)
    a = open(bin_path, 'rb').read()
    b = open(tmp_bin, 'rb').read()
    if a == b:
        print()
        print("OK ROUND-TRIP PASS: bit-perfect (" + str(len(a)) + " B)")
        return True
    diffs = sum(1 for x, y in zip(a, b) if x != y)
    print()
    print("FAIL ROUND-TRIP: " + str(diffs) + " bytes diff, " + str(len(a)) + " vs " + str(len(b)))
    for k, (x, y) in enumerate(zip(a, b)):
        if x != y:
            print("  @ %#x: %#04x != %#04x" % (k, x, y))
            if k > 10: break
    return False


USAGE = """单文件注入器. 批量处理请使用 bondage_batch.py

用法:
  python3 bondage_inject.py roundtrip <bin_path>
      原样提取再注入 bit-perfect 自检

  python3 bondage_inject.py inject <bin_path> <json_path> <out_bin> [opts...]

    可选参数 (任意顺序):
      --fixed              等长模式 (保持所有 text_off 不变, 超长截断)
      --names <path>       指定说话人表, 默认自动查找 *_names.json

  默认为变长模式 (重建文本池). 等长模式下被截断的条目会导出到
  <out_bin 同目录>/<out_bin stem>_fix.json, 可查阅溢出信息后修短重注入."""

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] in ('-h','--help','/?'):
        print(USAGE); sys.exit(0)
    if sys.argv[1] == 'roundtrip' and len(sys.argv) == 3:
        roundtrip_test(sys.argv[2])
    elif sys.argv[1] == 'inject' and len(sys.argv) >= 5:
        positional = sys.argv[2:5]
        rest = sys.argv[5:]
        mode = 'varlen'
        nt = None
        i = 0
        while i < len(rest):
            if rest[i] == '--fixed':
                mode = 'fixed'; i += 1
            elif rest[i] == '--names' and i + 1 < len(rest):
                nt = rest[i+1]; i += 2
            else:
                # 向后兼容: 第 4 个位置参数当 names
                if nt is None and not rest[i].startswith('--'):
                    nt = rest[i]; i += 1
                else:
                    print(f"未知参数: {rest[i]}"); print(USAGE); sys.exit(1)
        inject(positional[0], positional[1], positional[2],
               name_table_path=nt, mode=mode)
    else:
        print(USAGE); sys.exit(1)
