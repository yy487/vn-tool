#!/usr/bin/env python3
"""BONDAGE 引擎文本提取器 v3 - 正确的 name/msg 配对"""
import struct, sys, json, os, re
from bondage_ops import MAIN_OPS, SUB_OPS, parse_header, parse_labels


class Walker:
    def __init__(self, data: bytes, hdr: dict):
        self.data = data
        self.hdr = hdr
        self.pc = 0
    def u8(self):
        v = self.data[self.hdr['bc_base'] + self.pc]; self.pc += 1; return v
    def u16(self):
        v = struct.unpack_from('<H', self.data, self.hdr['bc_base'] + self.pc)[0]
        self.pc += 2; return v
    def consume_flag(self): self.pc += 3
    def consume_expr(self):
        while self.pc < self.hdr['bc_size']:
            if self.u8() == 0xFF: return
    def consume_switch(self):
        self.u8(); self.u16(); self.u16()
        n = self.u8()
        for _ in range(n): self.consume_flag()
    def read_str(self, text_off: int) -> str:
        start = self.hdr['text_base'] + text_off
        try: end = self.data.index(b'\x00', start)
        except ValueError: end = start + 200
        return self.data[start:end].decode('cp932', errors='replace')


def consume_fields(w: Walker, fields: list, record_text: list = None):
    for ftype, count in fields:
        for _ in range(count):
            if   ftype == 'u8':    w.u8()
            elif ftype == 'u16':   w.u16()
            elif ftype == 'flag':  w.consume_flag()
            elif ftype == 'expr':  w.consume_expr()
            elif ftype == 'switch_table': w.consume_switch()
            elif ftype in ('text', 'name_text'):
                t = w.u16()
                if record_text is not None:
                    record_text.append((ftype, t))
            else:
                raise ValueError(f"未知字段类型: {ftype}")


# 【XX】识别: 全角方括号包裹的短说话人标签
NAME_TAG_RE = re.compile(r'^【([^】]{1,20})】$')


def scan_block(w: Walker, start_pc: int, raw_events: list, seen_pc: set):
    """扫描代码块,输出原始事件序列 (不做 name 配对)
    event 格式: {'type': 'msg'|'title'|'msg_other', 'pc','sub','op_name','text_off','message'}
    """
    w.pc = start_pc
    visited = set()
    while w.pc < w.hdr['bc_size'] and w.pc not in visited:
        visited.add(w.pc)
        op_pc = w.pc
        op = w.u8()
        if op not in MAIN_OPS: return
        mnem, fields, flow = MAIN_OPS[op]
        if fields == 'dispatch_sub':
            sub = w.u8()
            if sub not in SUB_OPS: return
            sub_mnem, sub_fields, sub_kind = SUB_OPS[sub]
            texts = []
            try: consume_fields(w, sub_fields, texts)
            except (IndexError, struct.error): return
            for ftype, t in texts:
                if op_pc in seen_pc: continue
                txt = w.read_str(t)
                if ftype == 'name_text':
                    # SET_NAME_* 一律记为 'title' (场景/章节标题)
                    ev_type = 'title'
                else:
                    ev_type = sub_kind  # 'msg' 或 'msg_other'
                raw_events.append({
                    'type': ev_type, 'pc': op_pc, 'sub': sub,
                    'op_name': sub_mnem, 'text_off': t, 'message': txt,
                })
                seen_pc.add(op_pc)
        else:
            try: consume_fields(w, fields, None)
            except (IndexError, struct.error): return
            if flow == 'end': return


def pair_name_msg(raw_events: list) -> list:
    """把形如 [MSG '【幸江】', MSG '对话内容'] 的配对合并为单条带 name 的 MSG
    规则:
    - 如果一条 MSG 匹配 【XX】 模式, 且下一条 (按原顺序) 也是 MSG, 则:
      * 把【XX】作为下一条的 name
      * 原 【XX】 条目标记为跳过 (不导出)
    - 'title' 和 'msg_other' 保持独立
    """
    # 按 pc 升序 - 因为扫描顺序是按 label id, 同一代码块可能从不同 label 进入
    # 用 seen_pc 已去重, 这里按 pc 排序才能得到 "代码流" 的原顺序
    events = sorted(raw_events, key=lambda e: e['pc'])
    result = []
    skip = set()
    for i, e in enumerate(events):
        if i in skip: continue
        if e['type'] == 'msg':
            m = NAME_TAG_RE.match(e['message'])
            if m and i+1 < len(events) and events[i+1]['type'] == 'msg':
                nxt = events[i+1]
                # 下一条也不能是 【XX】 (避免 【A】+【B】 这种连续 name 行误配)
                if not NAME_TAG_RE.match(nxt['message']):
                    merged = dict(nxt)
                    merged['name'] = m.group(1)  # 去掉【】
                    merged['name_pc'] = e['pc']
                    merged['name_text_off'] = e['text_off']
                    result.append(merged)
                    skip.add(i+1)
                    continue
        result.append(e)
    return result


def extract(path: str) -> dict:
    data = open(path, 'rb').read()
    hdr = parse_header(data)
    labels = parse_labels(data, hdr)
    w = Walker(data, hdr)
    raw_events = []
    seen_pc = set()
    for lid in sorted(labels):
        scan_block(w, labels[lid], raw_events, seen_pc)
    paired = pair_name_msg(raw_events)
    # 重分配 id
    for i, e in enumerate(paired):
        e['id'] = i
    return {'header': hdr, 'labels': labels, 'entries': paired}


USAGE = """用法: python3 bondage_extract.py <输入.bin> [输出目录]

单文件提取器. 批量处理请使用 bondage_batch.py

示例:
  python3 bondage_extract.py 0081.bin
  python3 bondage_extract.py 0081.bin ./json/
"""

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help', '/?'):
        print(USAGE); sys.exit(0)
    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"[ERR] 文件不存在: {path}"); sys.exit(1)
    out_dir = sys.argv[2] if len(sys.argv) > 2 else '.'
    os.makedirs(out_dir, exist_ok=True)
    result = extract(path)
    hdr = result['header']
    entries = result['entries']
    from collections import Counter
    c = Counter(e['type'] for e in entries)
    print(f"bc_base={hdr['bc_base']:#x} text_base={hdr['text_base']:#x} "
          f"labels={len(result['labels'])} bc_size={hdr['bc_size']:#x}")
    print(f"提取 {len(entries)} 条  by type: {dict(c)}")
    n_with_name = sum(1 for e in entries if e.get('name'))
    print(f"含 name 配对: {n_with_name}")

    # 收集 name 表 (供翻译者参考)
    from collections import Counter
    name_counter = Counter(e.get('name') for e in entries if e.get('name'))

    # 输出 JSON
    json_out = []
    for e in entries:
        item = {'id': e['id'], 'pc': e['pc'], 'sub': e['sub'],
                'kind': e['type'], 'text_off': e['text_off']}
        if e.get('name'):
            item['name'] = e['name']
            item['name_pc'] = e['name_pc']
            item['name_text_off'] = e['name_text_off']
        item['message'] = e['message']
        item['src_msg'] = e['message']
        json_out.append(item)

    stem = os.path.basename(os.path.splitext(path)[0])
    # 输出 name 表 (单独文件, 翻译者维护)
    name_table_path = os.path.join(out_dir, stem + '_names.json')
    name_table = {n: {'count': c, 'translation': n} for n, c in name_counter.most_common()}
    with open(name_table_path, 'w', encoding='utf-8') as f:
        json.dump(name_table, f, ensure_ascii=False, indent=2)
    print(f"-> {name_table_path}  (name 表, 共 {len(name_table)} 个说话人)")

    outpath = os.path.join(out_dir, stem + '.json')
    with open(outpath, 'w', encoding='utf-8') as f:
        json.dump(json_out, f, ensure_ascii=False, indent=2)
    print(f"→ {outpath}  ({len(json_out)} 条)")

    # 样本
    print("\n样本前 15 条:")
    for e in json_out[:15]:
        t = e['kind']
        prefix = {'msg':'💬','title':'📖','msg_other':'★'}.get(t,'?')
        name = e.get('name','')
        name_str = f'[{name}] ' if name else ''
        print(f"  #{e['id']:4d} {prefix} {name_str}{e['message'][:50]}")
