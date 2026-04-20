#!/usr/bin/env python3
"""
ジサツのための101の方法 - FOB脚本文本提取/导入工具

FOB格式:
  [4 bytes]  函数数量
  [0x24 * N] 函数表 (name[0x1C] + magic[4] + offset[4])
  [...]      Bytecode区域

文本存储:
  opcode 0x03 0x00 + type[4] + null_terminated_sjis_string
  剧情文本以 \\e 开头, \\z 或 \\w\\n\\z 结尾
  \\p = 翻页, \\n = 换行

偏移引用:
  opcode 0x1F 0x00 + offset[2] (相对bytecode起始的偏移)
  opcode 0x22 0x00 类似
  函数表中的offset字段

导入策略:
  替换字符串后，扫描所有偏移引用并修正
"""

import struct
import os
import sys
import json
import re


def parse_fob_header(data: bytes):
    """解析FOB头部函数表，返回 (func_count, header_end, functions)"""
    func_count = struct.unpack_from('<I', data, 0)[0]
    functions = []
    off = 4
    for i in range(func_count):
        name_raw = data[off:off+0x1C]
        try:
            end = name_raw.index(0)
        except ValueError:
            end = 0x1C
        name = name_raw[:end].decode('ascii', errors='replace')
        magic = struct.unpack_from('<I', data, off+0x1C)[0]
        offset = struct.unpack_from('<I', data, off+0x20)[0]
        functions.append({'name': name, 'magic': magic, 'offset': offset,
                          'header_off': off+0x20})  # offset字段在文件中的位置
        off += 0x24
    return func_count, off, functions


def find_strings(data: bytes, header_end: int):
    """
    找到所有 03 00 type[4] string\\0 模式的字符串
    返回 list of dict: {file_off, type_val, str_start, str_end, raw, text, is_dialogue}
    """
    strings = []
    off = header_end
    while off < len(data) - 6:
        if data[off] == 0x03 and data[off+1] == 0x00:
            type_val = struct.unpack_from('<I', data, off+2)[0]
            str_start = off + 6
            p = str_start
            while p < len(data) and data[p] != 0:
                p += 1
            str_end = p  # null的位置
            raw = data[str_start:str_end]
            try:
                text = raw.decode('cp932')
            except UnicodeDecodeError:
                text = raw.decode('cp932', errors='replace')
            
            # 判断是否为剧情对话 (以\e开头)
            is_dialogue = text.startswith('\\e')
            
            strings.append({
                'file_off': off,       # 0x03的位置
                'type_off': off + 2,   # type字段位置
                'type_val': type_val,
                'str_start': str_start, # 字符串首字节位置
                'str_end': str_end,     # null位置
                'raw': raw,
                'text': text,
                'is_dialogue': is_dialogue,
            })
            off = str_end + 1
        else:
            off += 1
    return strings


def find_offset_refs(data: bytes, header_end: int):
    """
    扫描bytecode中所有包含偏移引用的指令
    返回 list of (file_position_of_offset_field, current_offset_value, field_size)
    
    已知包含偏移的指令:
    - 0x1F 0x00 offset[2]: 跳转/调用 (2字节LE偏移，相对bytecode起始)
    - 其他可能的偏移指令需要进一步逆向确认
    """
    refs = []
    off = header_end
    while off < len(data) - 3:
        if data[off] == 0x1F and data[off+1] == 0x00:
            val = struct.unpack_from('<H', data, off+2)[0]
            refs.append((off+2, val, 2))  # (位置, 值, 字节数)
            off += 4
        else:
            off += 1
    return refs


def split_dialogue(text: str):
    """
    将一个对话文本块拆分为独立的对话行
    返回 list of str (每行去掉控制符后的纯文本)
    """
    # 去掉开头的\e
    t = text
    if t.startswith('\\e'):
        t = t[2:]
    # 去掉结尾的\w\n\z 或 \z
    t = re.sub(r'\\[wz]$', '', t)
    t = re.sub(r'\\w\\n\\z$', '', t)
    
    # 按\p分割为页
    pages = t.split('\\p')
    lines = []
    for page in pages:
        # 去掉开头的\n
        page = page.lstrip('\\n')
        page = page.strip()
        if page:
            lines.append(page)
    return lines


def extract_texts(fob_path: str, output_path: str, all_strings: bool = False):
    """
    从FOB文件提取文本，输出为JSON
    all_strings: True则提取所有字符串，False只提取对话文本
    """
    with open(fob_path, 'rb') as f:
        data = f.read()
    
    func_count, header_end, functions = parse_fob_header(data)
    strings = find_strings(data, header_end)
    
    entries = []
    text_idx = 0
    for s in strings:
        if not all_strings and not s['is_dialogue']:
            continue
        
        entry = {
            'index': text_idx,
            'offset': f"0x{s['file_off']:04X}",
            'original': s['text'],
        }
        
        if s['is_dialogue']:
            # 拆分为行方便翻译
            lines = split_dialogue(s['text'])
            entry['lines'] = lines
            entry['translation'] = ''  # 翻译者填写
        
        entries.append(entry)
        text_idx += 1
    
    result = {
        'source_file': os.path.basename(fob_path),
        'total_strings': len(strings),
        'dialogue_count': sum(1 for s in strings if s['is_dialogue']),
        'entries': entries,
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    print(f"提取完成: {os.path.basename(fob_path)}")
    print(f"  总字符串: {len(strings)}")
    print(f"  对话文本: {result['dialogue_count']}")
    print(f"  输出: {output_path}")
    
    # 同时输出纯文本预览
    txt_path = output_path.rsplit('.', 1)[0] + '.txt'
    with open(txt_path, 'w', encoding='utf-8') as f:
        for entry in entries:
            if 'lines' in entry:
                f.write(f"===== [{entry['index']}] {entry['offset']} =====\n")
                for line in entry['lines']:
                    # 把FOB内的\n还原为实际换行显示
                    f.write(line.replace('\\n', '\n') + '\n')
                f.write('\n')
    
    print(f"  纯文本预览: {txt_path}")


def import_texts(fob_path: str, json_path: str, output_fob: str, encoding: str = 'cp932'):
    """
    将翻译后的文本导入FOB文件
    JSON中每个entry的 translation 字段为翻译后的完整文本块（含控制符）
    如果 translation 为空则保留原文
    encoding: 输出编码, 'cp932'=日文原版, 'gbk'=中文汉化
    """
    with open(fob_path, 'rb') as f:
        data = bytearray(f.read())
    
    with open(json_path, 'r', encoding='utf-8') as f:
        trans_data = json.load(f)
    
    func_count, header_end, functions = parse_fob_header(data)
    strings = find_strings(data, header_end)
    
    # 只处理对话文本
    dialogues = [s for s in strings if s['is_dialogue']]
    
    # 建立翻译映射 (index -> translation)
    trans_map = {}
    for entry in trans_data['entries']:
        if entry.get('translation', '').strip():
            trans_map[entry['index']] = entry['translation']
    
    if not trans_map:
        print("没有找到翻译内容，跳过")
        return
    
    # 收集所有需要替换的字符串及其新内容
    replacements = []  # (str_start, str_end, new_bytes)
    for i, dlg in enumerate(dialogues):
        if i in trans_map:
            new_text = trans_map[i]
            new_bytes = new_text.encode(encoding, errors='replace')
            replacements.append((dlg['str_start'], dlg['str_end'], new_bytes))
    
    if not replacements:
        print("没有实际需要替换的文本")
        return
    
    # 从后往前替换，这样前面的偏移不会被打乱
    # 但我们还需要修正偏移引用，所以用位移表方式
    
    # 构建位移表: 对于原始文件中的每个位置，计算替换后的偏移变化
    # shift_points: [(original_position, delta)]
    shift_points = []
    for str_start, str_end, new_bytes in replacements:
        old_len = str_end - str_start  # 原始字符串长度(不含null)
        new_len = len(new_bytes)
        delta = new_len - old_len
        if delta != 0:
            # 在str_end(null位置)之后的所有内容需要移动delta字节
            shift_points.append((str_end, delta))
    
    # 按位置排序
    shift_points.sort()
    
    # 计算累积位移函数: 给定原始位置，返回新位置的偏移变化量
    def calc_shift(orig_pos):
        total = 0
        for pos, delta in shift_points:
            if orig_pos > pos:
                total += delta
        return total
    
    # 重建文件
    # 方法: 将原始文件分段，在替换点插入新字符串
    # 先排序替换列表
    replacements.sort(key=lambda x: x[0])
    
    new_data = bytearray()
    prev_end = 0
    for str_start, str_end, new_bytes in replacements:
        # 复制替换点之前的原始数据
        new_data.extend(data[prev_end:str_start])
        # 写入新字符串
        new_data.extend(new_bytes)
        # 跳过原始字符串 (不含null，null会在下一段的开头被保留)
        prev_end = str_end
    # 复制剩余数据
    new_data.extend(data[prev_end:])
    
    # 修正偏移引用
    # 1. bytecode中的 0x1F 0x00 offset[2] 引用
    #    这些offset是相对bytecode起始(header_end)的偏移
    #    需要将它们从"原始bytecode偏移"映射到"新bytecode偏移"
    
    # 扫描新文件中的 0x1F 引用并修正
    # 但header_end不变(函数表大小不变)，所以bytecode偏移 = file_offset - header_end
    
    # 建立精确映射: 原始bytecode位置 -> 新bytecode位置
    # 使用shift_points: 原始file_pos经过所有shift后得到新file_pos
    # bytecode_offset = file_pos - header_end
    
    # 先修正新文件中的偏移引用
    off = header_end
    fixes = 0
    while off < len(new_data) - 3:
        if new_data[off] == 0x1F and new_data[off+1] == 0x00:
            old_bc_offset = struct.unpack_from('<H', new_data, off+2)[0]
            old_file_pos = old_bc_offset + header_end
            shift = calc_shift(old_file_pos)
            new_bc_offset = old_bc_offset + shift
            if new_bc_offset != old_bc_offset:
                struct.pack_into('<H', new_data, off+2, new_bc_offset & 0xFFFF)
                fixes += 1
            off += 4
        else:
            off += 1
    
    # 2. 函数表中的offset字段 (这些也是bytecode偏移)
    for func in functions:
        hoff = func['header_off']
        old_bc_offset = struct.unpack_from('<I', new_data, hoff)[0]
        old_file_pos = old_bc_offset + header_end
        shift = calc_shift(old_file_pos)
        new_bc_offset = old_bc_offset + shift
        if new_bc_offset != old_bc_offset:
            struct.pack_into('<I', new_data, hoff, new_bc_offset)
            fixes += 1
    
    with open(output_fob, 'wb') as f:
        f.write(new_data)
    
    print(f"导入完成: {output_fob}")
    print(f"  替换文本: {len(replacements)} 处")
    print(f"  修正偏移: {fixes} 处")
    print(f"  文件大小: {len(data)} -> {len(new_data)} ({len(new_data)-len(data):+d})")


def batch_extract(dat_dir: str, output_dir: str):
    """批量提取目录下所有FOB文件的文本"""
    os.makedirs(output_dir, exist_ok=True)
    
    fob_files = sorted([f for f in os.listdir(dat_dir) if f.upper().endswith('.FOB')])
    total_dialogues = 0
    
    for fn in fob_files:
        fob_path = os.path.join(dat_dir, fn)
        
        # 先检查是否含有对话文本
        with open(fob_path, 'rb') as f:
            data = f.read()
        
        try:
            func_count, header_end, _ = parse_fob_header(data)
        except:
            continue
        
        strings = find_strings(data, header_end)
        dialogues = [s for s in strings if s['is_dialogue']]
        
        if not dialogues:
            continue
        
        base = os.path.splitext(fn)[0]
        json_out = os.path.join(output_dir, f"{base}.json")
        extract_texts(fob_path, json_out)
        total_dialogues += len(dialogues)
        print()
    
    print(f"===== 批量提取完成 =====")
    print(f"  共处理 FOB 文件中含对话的文件")
    print(f"  总对话文本块: {total_dialogues}")


def batch_import(fob_dir: str, json_dir: str, output_dir: str, encoding: str = 'cp932'):
    """批量导入翻译"""
    os.makedirs(output_dir, exist_ok=True)
    
    json_files = sorted([f for f in os.listdir(json_dir) if f.endswith('.json')])
    
    for jf in json_files:
        json_path = os.path.join(json_dir, jf)
        with open(json_path, 'r', encoding='utf-8') as f:
            trans_data = json.load(f)
        
        src_name = trans_data.get('source_file', '')
        if not src_name:
            continue
        
        fob_path = os.path.join(fob_dir, src_name)
        if not os.path.exists(fob_path):
            print(f"源文件不存在: {fob_path}, 跳过")
            continue
        
        out_path = os.path.join(output_dir, src_name)
        import_texts(fob_path, json_path, out_path, encoding=encoding)
        print()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("ジサツのための101の方法 - FOB文本提取/导入工具")
        print()
        print("用法:")
        print(f"  python {sys.argv[0]} extract <file.fob> <output.json>")
        print(f"  python {sys.argv[0]} import  <orig.fob> <trans.json> <output.fob> [encoding]")
        print(f"  python {sys.argv[0]} batch-extract <fob_dir> <output_dir>")
        print(f"  python {sys.argv[0]} batch-import  <fob_dir> <json_dir> <output_dir> [encoding]")
        print()
        print("encoding: cp932(默认,日文) / gbk(中文汉化)")
        print()
        print("提取后编辑JSON中的 translation 字段填入翻译文本,")
        print("翻译文本需保留控制符: \\e(开始) \\p(翻页) \\n(换行) \\w(等待) \\z(结束)")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == 'extract' and len(sys.argv) >= 4:
        extract_texts(sys.argv[2], sys.argv[3])
    elif cmd == 'import' and len(sys.argv) >= 5:
        enc = sys.argv[5] if len(sys.argv) >= 6 else 'cp932'
        import_texts(sys.argv[2], sys.argv[3], sys.argv[4], encoding=enc)
    elif cmd == 'batch-extract' and len(sys.argv) >= 4:
        batch_extract(sys.argv[2], sys.argv[3])
    elif cmd == 'batch-import' and len(sys.argv) >= 5:
        enc = sys.argv[5] if len(sys.argv) >= 6 else 'cp932'
        batch_import(sys.argv[2], sys.argv[3], sys.argv[4], encoding=enc)
    else:
        print(f"未知命令或参数不足: {cmd}")
        sys.exit(1)
