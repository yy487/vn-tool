#!/usr/bin/env python3
"""
KrKr/KAG3 脚本注入工具
将翻译后的JSON写回.ks文件
"""
import json
from pathlib import Path
from typing import Dict, List


def inject_kag_script(original_ks: Path, translations: List[Dict], output_ks: Path):
    """注入单个.ks文件"""
    
    # 读取原始文件
    with open(original_ks, 'rb') as f:
        raw = f.read()
    
    content = raw.decode('cp932', errors='ignore')
    
    # 检测换行符类型
    if '\r\n' in content:
        newline = '\r\n'
        lines = content.split('\r\n')
    else:
        newline = '\n'
        lines = content.split('\n')
    
    # 按label建立翻译索引
    trans_map = {}
    for t in translations:
        key = (t['file'], t['label'])
        trans_map[key] = t
    
    # 处理每一行
    result_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # 检查是否是标签行
        import re
        label_match = re.match(r'^\*([^\|]+)', line.rstrip())
        
        if not label_match:
            # 非标签行,直接保留
            result_lines.append(line)
            i += 1
            continue
        
        label = label_match.group(1)
        key = (original_ks.name, label)
        
        # 查找翻译
        trans = trans_map.get(key)
        
        if not trans:
            # 没有翻译,保留原样
            result_lines.append(line)
            i += 1
            continue
        
        # 有翻译,重建这一段
        result_lines.append(line)  # 保留标签行
        i += 1
        
        # 跳过原始的 [cm2 voice="..."]
        if i < len(lines) and '[cm2' in lines[i]:
            # 写入新的cm2行(保留原voice)
            result_lines.append(f'[cm2 voice="{trans["voice"]}"]')
            i += 1
        
        # 跳过原始的 @name string="..."
        if i < len(lines) and '@name' in lines[i]:
            # 写入新的name行
            result_lines.append(f'@name string="{trans["name"]}"')
            i += 1
        
        # 跳过原始文本行,直到遇到下一个标签/命令
        while i < len(lines):
            text_line = lines[i].rstrip()
            
            if (text_line.startswith('*') or 
                text_line.startswith('@') or
                (text_line.startswith('[') and 
                 not text_line.startswith('[r]') and 
                 not text_line.startswith('[p') and
                 not text_line.startswith('[heart]'))):
                break
            
            # 跳过所有行,包括空行
            i += 1
        
        # 写入新文本
        message_text = trans['message']
        
        if isinstance(message_text, list):
            # 数组形式(旧格式兼容),逐行写入
            for line in message_text:
                result_lines.append(line)
        else:
            # 字符串形式,按\n分割成多行
            for line in message_text.split('\n'):
                result_lines.append(line)
    
    # 写入输出文件(CP932编码)
    output_content = newline.join(result_lines)
    
    with open(output_ks, 'wb') as f:
        f.write(output_content.encode('cp932', errors='ignore'))


def inject_directory(original_dir: Path, translation_json: Path, output_dir: Path):
    """注入整个目录"""
    
    # 读取翻译JSON
    with open(translation_json, 'r', encoding='utf-8') as f:
        translations = json.load(f)
    
    # 按文件分组
    file_groups = {}
    for t in translations:
        fname = t['file']
        if fname not in file_groups:
            file_groups[fname] = []
        file_groups[fname].append(t)
    
    # 创建输出目录
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 处理每个文件
    processed = 0
    for fname, trans_list in file_groups.items():
        original_ks = Path(original_dir) / fname
        output_ks = output_dir / fname
        
        if not original_ks.exists():
            print(f'警告: 找不到原始文件 {fname}')
            continue
        
        print(f'注入: {fname} ({len(trans_list)} 条)')
        inject_kag_script(original_ks, trans_list, output_ks)
        processed += 1
    
    print(f'\n注入完成: {processed} 个文件 -> {output_dir}')


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 4:
        print('用法: python kag_inject.py <原始脚本目录> <翻译json> <输出目录>')
        print('示例: python kag_inject.py ./scenario trans.json ./output')
        sys.exit(1)
    
    original_dir = Path(sys.argv[1])
    translation_json = Path(sys.argv[2])
    output_dir = Path(sys.argv[3])
    
    inject_directory(original_dir, translation_json, output_dir)
