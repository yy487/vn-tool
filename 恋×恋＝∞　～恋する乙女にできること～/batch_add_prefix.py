import json
import os
from pathlib import Path

def add_prefix_to_message(data, prefix="中文"):
    """给 message 字段添加前缀"""
    count = 0
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and 'message' in item:
                if item['message'] and isinstance(item['message'], str):
                    item['message'] = prefix + item['message']
                    count += 1
    elif isinstance(data, dict):
        if 'message' in data:
            if data['message'] and isinstance(data['message'], str):
                data['message'] = prefix + data['message']
                count += 1
    return data, count


def batch_process(folder_path='.', prefix="中文", pattern='*.json', output_folder=None):
    """
    批量处理文件夹中的所有 JSON 文件
    
    参数:
        folder_path: 文件夹路径，默认当前目录
        prefix: 要添加的前缀
        pattern: 文件匹配模式，默认 '*.json'
        output_folder: 输出文件夹，None 则覆盖原文件
    """
    folder = Path(folder_path)
    json_files = list(folder.glob(pattern))
    
    if not json_files:
        print(f"❌ 在 {folder_path} 中没有找到匹配 {pattern} 的文件")
        return
    
    print(f"找到 {len(json_files)} 个 JSON 文件\n")
    
    # 创建输出文件夹（如果指定了）
    if output_folder:
        output_path = Path(output_folder)
        output_path.mkdir(exist_ok=True)
        print(f"✓ 输出文件夹: {output_folder}\n")
    
    total_count = 0
    success_count = 0
    
    for json_file in json_files:
        try:
            # 读取
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 处理
            data, count = add_prefix_to_message(data, prefix)
            
            # 确定输出路径
            if output_folder:
                output_file = Path(output_folder) / json_file.name
            else:
                output_file = json_file
            
            # 保存
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            print(f"✓ {json_file.name}: 处理 {count} 条 message")
            total_count += count
            success_count += 1
            
        except Exception as e:
            print(f"✗ {json_file.name}: 处理失败 - {e}")
    
    print(f"\n{'='*50}")
    print(f"总计: 成功 {success_count}/{len(json_files)} 个文件")
    print(f"共处理 {total_count} 条 message 字段")


# ========== 使用示例 ==========

if __name__ == "__main__":
    
    # 方式 1: 处理当前目录所有 .json 文件（覆盖原文件）
    batch_process()
    
    # 方式 2: 处理指定文件夹（覆盖原文件）
    # batch_process('json_folder')
    
    # 方式 3: 保存到新文件夹（推荐！）
    # batch_process(folder_path='原始文件夹', output_folder='输出文件夹')
    
    # 方式 4: 只处理特定文件名（例如 00000.json, 00001.json 等）
    # batch_process(pattern='0*.json')
    
    # 方式 5: 自定义前缀
    # batch_process(prefix="【测试】")