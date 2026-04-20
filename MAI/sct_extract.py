#!/usr/bin/env python3
"""
sct_extract.py - MSC/SCT 脚本文本提取工具
引擎: NikuyokuH (MSC格式, HS engine)
输出: GalTransl兼容JSON (name/message/id)

用法: python sct_extract.py <input.sct> [output.json]
"""

import sys
import os
import json
import struct


def extract_texts(data, encoding='cp932'):
    """从SCT数据中提取所有以##终止的文本段。"""
    texts = []
    i = 0
    while i < len(data) - 1:
        if data[i] == 0x23 and data[i + 1] == 0x23:
            start = i - 1
            while start > 0 and data[start] != 0x00:
                start -= 1
            start += 1
            if start < i:
                raw = data[start:i + 2]
                try:
                    txt = raw.decode(encoding)
                    texts.append((start, raw, txt))
                except UnicodeDecodeError:
                    pass
            i += 2
        else:
            i += 1
    return texts


def build_voice_tag_index(data):
    """
    扫描全文件，收集所有 _vXXXX 语音标签的位置。
    返回排序后的 (offset, name) 列表。
    """
    voice_map = {
        b'_vMizu': 'みずほ', b'_vAman': '天音', b'_vHina': 'ひなの',
        b'_vFnsn': '主人公', b'_vAki': 'あき', b'_vMiso': 'みそ',
        b'_vMuto': 'むとう', b'_vEtcf': 'その他(女)', b'_vMixs': 'ミックス',
    }
    tags = []
    for tag_bytes, name in voice_map.items():
        pos = 0
        while True:
            idx = data.find(tag_bytes, pos)
            if idx == -1:
                break
            tags.append((idx, name))
            pos = idx + 1
    tags.sort()
    return tags


def detect_speaker(tag_index, text_offset):
    """
    用二分搜索在全局语音标签索引中找到文本前最近的 _vXXXX 标签。
    只对以「或『开头的对话使用。
    """
    import bisect
    offsets = [t[0] for t in tag_index]
    idx = bisect.bisect_right(offsets, text_offset) - 1
    if idx >= 0:
        return tag_index[idx][1]
    return ''


def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <input.sct> [output.json]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) >= 3 else os.path.splitext(input_path)[0] + '.json'

    with open(input_path, 'rb') as f:
        data = f.read()

    if data[:4] != b'MSC\n':
        print(f"[警告] 文件头非 'MSC\\n'")
    if len(data) >= 8:
        hdr_size = struct.unpack_from('<I', data, 4)[0]
        if hdr_size != len(data):
            print(f"[警告] header filesize={hdr_size} != actual={len(data)}")

    texts = extract_texts(data)
    print(f"[提取] {len(texts)} 段文本")
    dialogue = sum(1 for _, _, t in texts if t.startswith('「') or t.startswith('『'))
    print(f"  对话={dialogue}  叙述={len(texts)-dialogue}")
    sizes = [len(r) for _, r, _ in texts]
    print(f"  字节: min={min(sizes)} max={max(sizes)} avg={sum(sizes)//len(sizes)}")

    # 构建全局语音标签索引
    tag_index = build_voice_tag_index(data)
    print(f"  语音标签: {len(tag_index)}")

    entries = []
    for offset, raw, txt in texts:
        name = ''
        if txt.startswith('「') or txt.startswith('『'):
            name = detect_speaker(tag_index, offset)
        entries.append({'id': f"sct_{offset:06x}", 'name': name, 'message': txt})

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"[输出] {output_path} ({len(entries)} 条)")
    for e in entries[:5]:
        n = f"[{e['name']}] " if e['name'] else ''
        print(f"  {e['id']}: {n}{e['message'][:50]}...")


if __name__ == '__main__':
    main()
