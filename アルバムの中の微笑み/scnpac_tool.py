#!/usr/bin/env python3
"""
scnpac_tool.py - Seraph引擎 ScnPac.Dat 解包/封包工具

ScnPac.Dat 结构:
  u32        count          脚本条目数
  u32[count+1] offsets      偏移表(末项为sentinel)
  bytes      entries        脚本条目数据(entry[i] = data[offsets[i]:offsets[i+1]])
  bytes      archpac_index  ArchPac.Dat的索引数据(嵌入在ScnPac尾部)

  entry[0]: 配置(24B: 纹理尺寸+屏幕分辨率)
  entry[1]: 占位(8B全零)
  entry[2..N-1]: 脚本字节码
"""

import struct
import os
import sys
import json


def unpack(scnpac_path, out_dir):
    """解包 ScnPac.Dat → 独立文件"""
    with open(scnpac_path, 'rb') as f:
        data = f.read()

    count = struct.unpack_from('<I', data, 0)[0]
    offsets = [struct.unpack_from('<I', data, 4 + i * 4)[0] for i in range(count + 1)]

    os.makedirs(out_dir, exist_ok=True)

    # 导出每个脚本条目
    manifest = {'count': count, 'entries': []}
    for i in range(count):
        start, end = offsets[i], offsets[i + 1]
        entry_data = data[start:end]
        fname = f'entry_{i:04d}.bin'
        with open(os.path.join(out_dir, fname), 'wb') as f:
            f.write(entry_data)
        manifest['entries'].append({
            'index': i,
            'file': fname,
            'offset': start,
            'size': len(entry_data),
        })

    # 导出ArchPac索引(尾部数据)
    tail_start = offsets[count]
    if tail_start < len(data):
        tail_data = data[tail_start:]
        tail_fname = '_archpac_index.bin'
        with open(os.path.join(out_dir, tail_fname), 'wb') as f:
            f.write(tail_data)
        manifest['archpac_index'] = {
            'file': tail_fname,
            'offset': tail_start,
            'size': len(tail_data),
        }

        # 解析ArchPac索引元信息
        n_archives = struct.unpack_from('<I', tail_data, 0)[0]
        total_files = struct.unpack_from('<I', tail_data, 4)[0]
        archives = []
        for j in range(n_archives):
            base = struct.unpack_from('<I', tail_data, 8 + j * 8)[0]
            cnt = struct.unpack_from('<I', tail_data, 8 + j * 8 + 4)[0]
            archives.append({'base_offset': f'0x{base:08X}', 'file_count': cnt})
        manifest['archpac_index']['archives'] = archives
        manifest['archpac_index']['total_files'] = total_files

    # 保存manifest
    with open(os.path.join(out_dir, '_manifest.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f'解包完成: {count} 个脚本条目 → {out_dir}/')
    if tail_start < len(data):
        print(f'  ArchPac索引: {len(data) - tail_start} bytes ({total_files} files across {n_archives} archives)')
    print(f'  entry[0]: 配置 ({manifest["entries"][0]["size"]}B)')
    print(f'  entry[1]: 占位 ({manifest["entries"][1]["size"]}B)')
    print(f'  entry[2..{count-1}]: 脚本 ({count-2} 个)')


def repack(in_dir, scnpac_path):
    """封包 独立文件 → ScnPac.Dat"""
    with open(os.path.join(in_dir, '_manifest.json'), 'r', encoding='utf-8') as f:
        manifest = json.load(f)

    count = manifest['count']

    # 读取所有entry
    entries_data = []
    for entry in manifest['entries']:
        with open(os.path.join(in_dir, entry['file']), 'rb') as f:
            entries_data.append(f.read())

    # 读取ArchPac索引
    tail_data = b''
    if 'archpac_index' in manifest:
        with open(os.path.join(in_dir, manifest['archpac_index']['file']), 'rb') as f:
            tail_data = f.read()

    # 计算偏移表
    header_size = 4 + (count + 1) * 4  # count字段 + offsets数组
    current_offset = header_size
    offsets = []
    for ed in entries_data:
        offsets.append(current_offset)
        current_offset += len(ed)
    offsets.append(current_offset)  # sentinel

    # 组装文件
    out = bytearray()
    out.extend(struct.pack('<I', count))
    for off in offsets:
        out.extend(struct.pack('<I', off))
    for ed in entries_data:
        out.extend(ed)
    out.extend(tail_data)

    with open(scnpac_path, 'wb') as f:
        f.write(out)

    print(f'封包完成: {count} 个条目 → {scnpac_path}')
    print(f'  文件大小: {len(out)} bytes')


def main():
    if len(sys.argv) < 3:
        print('用法:')
        print('  解包: python scnpac_tool.py unpack SCNPAC.DAT output_dir/')
        print('  封包: python scnpac_tool.py repack input_dir/ SCNPAC.DAT')
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == 'unpack':
        scnpac_path = sys.argv[2]
        out_dir = sys.argv[3] if len(sys.argv) > 3 else 'scnpac_out'
        unpack(scnpac_path, out_dir)
    elif cmd == 'repack':
        in_dir = sys.argv[2]
        scnpac_path = sys.argv[3] if len(sys.argv) > 3 else 'SCNPAC_new.DAT'
        repack(in_dir, scnpac_path)
    else:
        print(f'未知命令: {cmd}')
        sys.exit(1)


if __name__ == '__main__':
    main()
