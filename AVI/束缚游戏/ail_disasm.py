#!/usr/bin/env python3
"""
ail_disasm.py - AIL/BONDAGE 字节码反汇编 & 文本指针扫描

依赖: op_table_v2.json (从 EXE 反编译自动提取的 opcode 参数序列)

策略:
1. 从所有 label 入口尝试线性反汇编
2. 收集每个"成功走通"的 op 实例,把命中文本起点的 u16 记为真指针
3. 输出: 文本指针列表 + 每个文本被引用的位置 (用于后续注入)

当前限制:
- 60/172 个 op 已通过验证 (能完整跑通某个 label 块)
- 剩余 op 字节数对错未知,会导致部分 label 反汇编中断
- 但对"提取文本"已经够用 (每个文本只要被引用一次就能找到)
"""

import json, struct, sys

def load_bin(path):
    with open(path, 'rb') as f:
        d = f.read()
    f4 = struct.unpack_from('<H', d, 4)[0]
    f6 = struct.unpack_from('<H', d, 6)[0]
    n = f4 >> 1
    arr1_end = 12 + n * 2
    data_start = arr1_end + f6
    arr1 = list(struct.unpack_from(f'<{n}H', d, 12))
    labels = list(zip(arr1[0::2], arr1[1::2]))
    return {
        'header': d[:12],
        'labels': labels,
        'bytecode': d[arr1_end:data_start],
        'text_blob': d[data_start:],
        'arr1_end': arr1_end,
        'data_start': data_start,
    }


def list_text_starts(text_blob):
    """返回 {offset: string} 的字典,offset 是文本区相对偏移"""
    starts = {}
    i = 0
    while i < len(text_blob):
        if text_blob[i] == 0:
            i += 1; continue
        end = text_blob.find(b'\x00', i)
        if end < 0: end = len(text_blob)
        try:
            s = text_blob[i:end].decode('cp932')
            starts[i] = s
        except UnicodeDecodeError:
            pass
        i = end + 1
    return starts


def disasm_label(bc, start, end, op_table):
    """从 start 反汇编到 end. 返回 (ops_decoded, success_bool)"""
    pc = start
    decoded = []
    while pc < end:
        if pc >= len(bc):
            return decoded, False
        op = bc[pc]
        info = op_table.get(op)
        if info is None:
            return decoded, False
        params = bc[pc+1 : pc+1+info['bytes']]
        if len(params) < info['bytes']:
            return decoded, False
        text_ptr = None
        if info['text_byte_off'] is not None:
            tp_off = info['text_byte_off']
            if tp_off + 2 <= len(params):
                text_ptr = struct.unpack_from('<H', params, tp_off)[0]
        decoded.append({
            'pc': pc,
            'op': op,
            'params': params,
            'text_ptr': text_ptr,
            'param_text_offset': pc + 1 + (info['text_byte_off'] or 0),
        })
        pc += 1 + info['bytes']
    return decoded, (pc == end)


def scan_text_pointers(info_dict, op_table):
    """扫所有 label,收集"完整跑通的 label 里"提取出的文本指针"""
    bc = info_dict['bytecode']
    text_blob = info_dict['text_blob']
    labels = info_dict['labels']
    text_starts = list_text_starts(text_blob)

    # 真·文本指针: 在某个成功反汇编的 label 里被识别出的指针
    # key=文本起点偏移, value=[(label_id, byte_offset_in_bc), ...]
    text_refs = {}  # text_offset -> list of (bc_offset where the u16 ptr lives)
    success_labels = 0
    failed_labels = 0

    for i, (lid, loff) in enumerate(labels):
        end_off = labels[i+1][1] if i+1 < len(labels) else len(bc)
        decoded, success = disasm_label(bc, loff, end_off, op_table)
        if success:
            success_labels += 1
        else:
            failed_labels += 1
        for ins in decoded:
            tp = ins['text_ptr']
            if tp is not None and tp in text_starts:
                text_refs.setdefault(tp, []).append(ins['param_text_offset'])

    return {
        'text_starts': text_starts,
        'text_refs': text_refs,
        'success_labels': success_labels,
        'failed_labels': failed_labels,
    }


def main():
    if len(sys.argv) < 3:
        print('用法: ail_disasm.py <op_table_v2.json> <0082.bin>')
        sys.exit(1)

    with open(sys.argv[1]) as f:
        op_table = {int(k): v for k, v in json.load(f).items()}

    info_dict = load_bin(sys.argv[2])
    print(f'字节码 {len(info_dict["bytecode"])} B,文本区 {len(info_dict["text_blob"])} B,labels {len(info_dict["labels"])}')

    result = scan_text_pointers(info_dict, op_table)

    print(f'\n=== 反汇编统计 ===')
    print(f'成功跑通 label: {result["success_labels"]}/{len(info_dict["labels"])}')
    print(f'失败 label:     {result["failed_labels"]}')
    print(f'\n=== 文本指针统计 ===')
    print(f'文本起点数:        {len(result["text_starts"])}')
    print(f'被引用的文本数:    {len(result["text_refs"])}')
    print(f'未被引用的文本数:  {len(result["text_starts"]) - len(result["text_refs"])}')

    # 抽样显示
    print(f'\n=== 已识别文本样本 (前15) ===')
    items = sorted(result['text_refs'].items())[:15]
    for off, refs in items:
        text = result['text_starts'][off]
        print(f'  +{off:5} ({len(refs)}次引用): {text[:50]}')


if __name__ == '__main__':
    main()
