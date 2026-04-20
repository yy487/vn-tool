#!/usr/bin/env python3
"""
KrKr/KAG3 脚本提取工具
适用于 @cm2 + @name 格式的变体
"""
import re
import json
from pathlib import Path
from typing import List, Dict


def extract_kag_script(ks_path: Path) -> List[Dict]:
    """提取单个.ks文件的文本"""
    
    # 读取文件(CP932编码)
    with open(ks_path, 'rb') as f:
        raw = f.read()
    
    content = raw.decode('cp932', errors='ignore')
    
    entries = []
    lines = content.split('\n')
    
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        
        # 匹配标签行 *xxx|...
        label_match = re.match(r'^\*([^\|]+)', line)
        if not label_match:
            i += 1
            continue
        
        label = label_match.group(1)
        
        # 下一行应该是 [cm2 voice="..."]
        i += 1
        if i >= len(lines):
            break
        
        cm2_line = lines[i].rstrip()
        voice_match = re.search(r'\[cm2\s+voice="([^"]*)"\]', cm2_line)
        if not voice_match:
            continue
        
        voice = voice_match.group(1)
        
        # 下一行是 @name string="..."
        i += 1
        if i >= len(lines):
            break
        
        name_line = lines[i].rstrip()
        name_match = re.search(r'@name\s+string="([^"]*)"', name_line)
        if not name_match:
            continue
        
        name = name_match.group(1)
        
        # 收集后续文本行,直到遇到下一个标签或命令
        i += 1
        message_lines = []
        while i < len(lines):
            text_line = lines[i].rstrip()
            
            # 遇到下一个标签或命令,停止
            if (text_line.startswith('*') or 
                text_line.startswith('@') or
                (text_line.startswith('[') and 
                 not text_line.startswith('[r]') and 
                 not text_line.startswith('[p') and
                 not text_line.startswith('[heart]'))):
                break
            
            # 保存所有行,包括空行
            message_lines.append(text_line)
            i += 1
        
        # 合并为单个字符串
        message = '\n'.join(message_lines)
        
        # 跳过完全空白的文本块
        if not message.strip():
            continue
        
        entry = {
            'label': label,
            'voice': voice,
            'name': name,
            'message': message
        }
        
        entries.append(entry)
    
    return entries


def extract_directory(script_dir: Path, output_json: Path):
    """提取整个目录的脚本"""
    
    script_dir = Path(script_dir)
    all_entries = []
    
    ks_files = sorted(script_dir.glob('*.ks'))
    
    print(f'找到 {len(ks_files)} 个 .ks 文件')
    
    for ks_file in ks_files:
        print(f'提取: {ks_file.name}')
        entries = extract_kag_script(ks_file)
        
        # 添加文件信息
        for e in entries:
            e['file'] = ks_file.name
        
        all_entries.extend(entries)
    
    # 添加唯一ID
    for i, e in enumerate(all_entries):
        e['id'] = i
    
    # 写入JSON
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(all_entries, f, ensure_ascii=False, indent=2)
    
    print(f'\n提取完成: {len(all_entries)} 条文本 -> {output_json}')


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 3:
        print('用法: python kag_extract.py <脚本目录> <输出json>')
        print('示例: python kag_extract.py ./scenario output.json')
        sys.exit(1)
    
    script_dir = Path(sys.argv[1])
    output_json = Path(sys.argv[2])
    
    extract_directory(script_dir, output_json)
