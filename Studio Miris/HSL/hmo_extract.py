#!/usr/bin/env python3
"""
HMO 消息文本提取工具 (インタールード / Interlude 引擎)
格式: msg.dat (magic='HMO ', XOR 0xFF 加密)

用法: python hmo_extract.py msg.dat -o msg_texts.json

HMO 文件格式 (来自 exe FUN_00413cb0):
  0   magic (4)     = 'HMO '
  4   version (2)   = 100
  6   data_off (4)  = text data 区起始绝对偏移
  10  count (4)     = 消息总数
  14  data_size (4) = text data 区字节数
  18  offsets (count*4)  = 每条相对 data_off 的偏移
  data_off..end: 消息数据区, 每条 = [u32 size][size bytes XOR 0xFF 加密]

控制码 (解密后):
  \a <name> ;            角色名
  \o <voice.ogg>,<grp> ; 语音文件
  \n                     换行
  \k                     消息结尾

SNR 中 opcode 0x80 用 u32 绝对索引引用本文件, 所以汉化时只要保持 count 不变,
SNR 完全不需要修改。
"""
import struct
import json
import os


def parse_hmo(data):
    magic = data[0:4]
    if magic != b'HMO ':
        raise ValueError(f'不是 HMO 文件: magic={magic!r}')

    version   = struct.unpack_from('<H', data, 4)[0]
    data_off  = struct.unpack_from('<I', data, 6)[0]
    count     = struct.unpack_from('<I', data, 10)[0]
    data_size = struct.unpack_from('<I', data, 14)[0]

    index_off = 18
    # 验证结构一致性
    assert index_off + count * 4 == data_off, \
        f'index 表末尾 0x{index_off + count*4:x} != data_off 0x{data_off:x}'
    assert data_off + data_size == len(data), \
        f'文件尾 0x{len(data):x} != data_off + data_size 0x{data_off + data_size:x}'

    offsets = [struct.unpack_from('<I', data, index_off + i * 4)[0] for i in range(count)]

    return {
        'magic': 'HMO',
        'version': version,
        'count': count,
        'data_off': data_off,
        'data_size': data_size,
        'index_off': index_off,
        'offsets': offsets,
    }


def read_entry(data, info, i):
    """读取第 i 条 entry 的原始字节 (已解密)"""
    abs_off = info['data_off'] + info['offsets'][i]
    size = struct.unpack_from('<I', data, abs_off)[0]
    raw = data[abs_off + 4: abs_off + 4 + size]
    dec = bytes(b ^ 0xFF for b in raw)
    return dec


def parse_controls(msg_str):
    """解析消息, 分离出 name / voice / text / 尾部控制码.
    msg_str 是已解码的 cp932 字符串 (含 \\a \\o \\k \\n 等转义)."""
    name = ''
    voice = ''
    text = msg_str

    # \a <name> ;
    if text.startswith('\\a'):
        rest = text[2:]
        if ';' in rest:
            semi = rest.index(';')
            name = rest[:semi]
            text = rest[semi + 1:]

    # \o <voice>,<grp> ;
    if text.startswith('\\o'):
        rest = text[2:]
        if ';' in rest:
            semi = rest.index(';')
            voice = rest[:semi]
            text = rest[semi + 1:]

    # 去掉末尾 \k
    if text.endswith('\\k'):
        text = text[:-2]

    return name, voice, text


def extract_texts(data, info, filename=''):
    entries = []
    decode_fail = 0
    for i in range(info['count']):
        raw = read_entry(data, info, i)
        try:
            s = raw.decode('cp932')
        except UnicodeDecodeError:
            decode_fail += 1
            s = raw.decode('cp932', errors='replace')

        name, voice, text = parse_controls(s)
        entries.append({
            'id': f'{filename}_{i:05d}',
            'name': name,
            'message': text,
            'voice': voice,
        })
    if decode_fail:
        print(f'  警告: {decode_fail} 条解码异常')
    return entries


def main():
    import argparse
    p = argparse.ArgumentParser(description='HMO 文本提取')
    p.add_argument('files', nargs='+')
    p.add_argument('-o', '--output', default='msg_texts.json')
    args = p.parse_args()

    all_entries = []
    for fpath in args.files:
        fname = os.path.splitext(os.path.basename(fpath))[0]
        data = open(fpath, 'rb').read()
        info = parse_hmo(data)
        entries = extract_texts(data, info, fname)
        all_entries.extend(entries)
        print(f'{fpath}: HMO v{info["version"]}, {info["count"]} msgs, '
              f'data_size=0x{info["data_size"]:x}')

    out = [{'id': e['id'], 'name': e['name'],
            'message': e['message'], 'voice': e['voice']}
           for e in all_entries]
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f'导出 {len(out)} 条 → {args.output}')


if __name__ == '__main__':
    main()
