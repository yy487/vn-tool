#!/usr/bin/env python3
"""
HMO 消息文本注入工具 (インタールード / Interlude 引擎)
格式: msg.dat (magic='HMO ', XOR 0xFF 加密)

用法: python hmo_inject.py msg.dat -i msg_texts.json -o output/

注入流程:
  1. 按原样读取所有 entry (解密后字节)
  2. 对 JSON 里 message 不同于原文的 entry, 重建: prefix(\\a..;\\o..;) + new_text + \\k
  3. 重算 offsets, 重加密, 重写 header 的 data_off 和 data_size 字段
  4. SNR 中的 msg_id 是绝对索引, 数量不变就无需改 SNR

注意: message 字段里的 \\n (双字符) 保持原样, 游戏引擎按字面 \\n 识别换行.
"""
import struct
import json
import os


def parse_hmo(data):
    assert data[:4] == b'HMO ', f'bad magic: {data[:4]!r}'
    version   = struct.unpack_from('<H', data, 4)[0]
    data_off  = struct.unpack_from('<I', data, 6)[0]
    count     = struct.unpack_from('<I', data, 10)[0]
    data_size = struct.unpack_from('<I', data, 14)[0]
    index_off = 18
    assert index_off + count * 4 == data_off
    assert data_off + data_size == len(data)
    offsets = [struct.unpack_from('<I', data, index_off + i * 4)[0] for i in range(count)]
    return {'version': version, 'count': count, 'data_off': data_off,
            'data_size': data_size, 'index_off': index_off, 'offsets': offsets}


def read_entry_dec(data, info, i):
    """返回第 i 条已解密的完整 entry 字节"""
    abs_off = info['data_off'] + info['offsets'][i]
    size = struct.unpack_from('<I', data, abs_off)[0]
    raw = data[abs_off + 4: abs_off + 4 + size]
    return bytes(b ^ 0xFF for b in raw)


def split_controls(msg_bytes):
    """把解密后的 entry 字节拆成: prefix(\\a..;\\o..;) + body + suffix(\\k)
    body 内部可能含 \\n, 作为内容的一部分保留."""
    prefix = b''
    body = bytes(msg_bytes)

    # \a <name> ;
    if body.startswith(b'\\a'):
        semi = body.find(b';', 2)
        if semi >= 0:
            prefix += body[:semi + 1]
            body = body[semi + 1:]

    # \o <voice>,<grp> ;
    if body.startswith(b'\\o'):
        semi = body.find(b';', 2)
        if semi >= 0:
            prefix += body[:semi + 1]
            body = body[semi + 1:]

    # 尾部 \k
    suffix = b''
    if body.endswith(b'\\k'):
        suffix = b'\\k'
        body = body[:-2]

    return prefix, body, suffix


def build_entry(prefix, new_text_bytes, suffix):
    """组装新 entry (未加密字节)"""
    return prefix + new_text_bytes + suffix


def inject(data, info, trans_map):
    """trans_map: {int_index: new_message_str}"""
    new_bodies = []  # 每项是 (new_entry_bytes_decrypted,)
    changed = 0
    encode_fail = 0

    for i in range(info['count']):
        orig = read_entry_dec(data, info, i)

        if i not in trans_map:
            new_bodies.append(orig)
            continue

        prefix, body, suffix = split_controls(orig)
        orig_text = body.decode('cp932', errors='replace')
        new_text  = trans_map[i]

        if new_text == orig_text:
            new_bodies.append(orig)
            continue

        try:
            new_text_b = new_text.encode('cp932')
        except UnicodeEncodeError as e:
            encode_fail += 1
            if encode_fail <= 5:
                print(f'  警告 [{i}]: cp932 编码失败 ({e}), 保留原文')
            new_bodies.append(orig)
            continue

        new_entry = build_entry(prefix, new_text_b, suffix)
        new_bodies.append(new_entry)
        changed += 1

    if encode_fail > 5:
        print(f'  (共 {encode_fail} 条编码失败)')

    # 重算 offsets 和 data_size
    new_offsets = []
    pos = 0
    enc_blob = bytearray()
    for entry in new_bodies:
        new_offsets.append(pos)
        # 每条 entry 存储格式: [u32 size][size bytes XOR 0xFF]
        size = len(entry)
        enc_blob.extend(struct.pack('<I', size))
        enc_blob.extend(bytes(b ^ 0xFF for b in entry))
        pos += 4 + size

    new_data_size = pos
    # data_off 不变 (依赖 count, count 没变)
    data_off = info['data_off']

    # 组装文件
    out = bytearray()
    out.extend(data[:18])  # header
    # 改写 data_size 字段 (@14)
    struct.pack_into('<I', out, 14, new_data_size)
    # index table
    for off in new_offsets:
        out.extend(struct.pack('<I', off))
    assert len(out) == data_off, f'{len(out)} != {data_off}'
    # encrypted data region
    out.extend(enc_blob)

    return bytes(out), changed


def verify(new_data):
    info = parse_hmo(new_data)
    print(f'  验证: HMO v{info["version"]}, {info["count"]} msgs, '
          f'data_size=0x{info["data_size"]:x} ✅')
    # 抽样解几条
    for i in (0, info['count'] // 2, info['count'] - 1):
        dec = read_entry_dec(new_data, info, i)
        try:
            s = dec.decode('cp932')
            print(f'    [{i}] ok, len={len(dec)}')
        except Exception as e:
            print(f'    [{i}] 解码失败: {e}')


def main():
    import argparse
    p = argparse.ArgumentParser(description='HMO 文本注入')
    p.add_argument('files', nargs='+')
    p.add_argument('-i', '--input', required=True, help='翻译 JSON')
    p.add_argument('-o', '--outdir', default='output')
    args = p.parse_args()

    with open(args.input, 'r', encoding='utf-8') as f:
        translated = json.load(f)

    trans_by_file = {}
    for t in translated:
        fid = t['id'].rsplit('_', 1)[0]
        trans_by_file.setdefault(fid, []).append(t)

    os.makedirs(args.outdir, exist_ok=True)

    for fpath in args.files:
        fname = os.path.splitext(os.path.basename(fpath))[0]
        data = open(fpath, 'rb').read()
        info = parse_hmo(data)

        tlist = trans_by_file.get(fname, [])
        tmap = {}
        for t in tlist:
            try:
                idx = int(t['id'].rsplit('_', 1)[1])
                tmap[idx] = t['message']
            except ValueError:
                continue

        new_data, changed = inject(data, info, tmap)
        outpath = os.path.join(args.outdir, os.path.basename(fpath))
        with open(outpath, 'wb') as f:
            f.write(new_data)
        print(f'{fpath}: {info["count"]} msgs, '
              f'{len(data)} → {len(new_data)} bytes, 变更: {changed}')
        verify(new_data)


if __name__ == '__main__':
    main()
