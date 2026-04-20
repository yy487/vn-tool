#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
g2_unpack.py - Glib2 .g2 / .stx 资源包解包器
移植自 GARbro/ArcG2.cs (morkt)

格式概要:
  Header (0x5C, 整体加密 key=0x8465B49B):
    "GLibArchiveData2.\\0" + version('0'/'1') + ...
    +0x14 Key3, +0x24 Key2, +0x34 Key1, +0x44 Key0  (4 把 index 解密 key)
    +0x54 index_offset, +0x58 index_size

  Index (4 层洋葱解密, 顺序 Key0→Key1→Key2→Key3, ping-pong):
    "CDBD" + count(4B) + ? + info_base_off(4B@8) + ...
    从 0x10 开始: count × 0x18B 目录条目

  Entry data (每 0x20000 字节一 chunk, 4 把 key 循环):
    G2Scheme.Decrypt: src/dst byte 重排 + 两层 byte permutation
"""
import os, sys, struct, argparse

# ============================================================
# Permutation 表 (与源码完全一致)
# ============================================================
MUTATION_ORDER = [
    [3,2,1,0], [0,2,1,3], [1,0,3,2],
    [3,0,2,1], [2,1,3,0], [3,2,1,0],
]

def rot_byte_r(x, n):
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF if n else x & 0xFF

def rot_byte_l(x, n):
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF if n else x & 0xFF

PERMUTATIONS = [
    lambda i, x: rot_byte_r(x & 0xFF, i),       # 0
    lambda i, x: (x ^ i) & 0xFF,                # 1
    lambda i, x: (~x) & 0xFF,                   # 2
    lambda i, x: (~(x - 100)) & 0xFF,           # 3
    lambda i, x: (x + i) & 0xFF,                # 4
    lambda i, x: rot_byte_l(x & 0xFF, 4),       # 5
]

# 完整 900 个 hash (从源码原样搬过来, 保存在 hashes.txt)
with open('hashes.txt') as _f:
    PERMUTATION_HASHES = [int(x, 16) for x in _f.read().split(',')]
assert len(PERMUTATION_HASHES) == 900


class G2Scheme:
    def __init__(self, src_order, dst_order, first_perm, second_perm):
        self.src_order = src_order
        self.dst_order = dst_order
        self.first  = first_perm
        self.second = second_perm

    def decrypt(self, inp, in_off, out, out_off, length):
        i = 0
        end_aligned = length & ~3
        while i < end_aligned:
            src = in_off  + (i & ~3) + self.src_order[i & 3]
            dst = out_off + (i & ~3) + self.dst_order[i & 3]
            v = self.first(i, inp[src])
            v = self.second(i, v)
            out[dst] = v
            i += 1
        while i < length:
            v = self.first(i, inp[in_off + i])
            v = self.second(i, v)
            out[out_off + i] = v
            i += 1


def make_scheme(key):
    h = ((key * 0x5F) >> 13) & 0xFFFF
    try:
        i = PERMUTATION_HASHES.index(h)
    except ValueError:
        return None
    src_order = i // 150
    dst_order = i // 30 - 5 * src_order
    if dst_order >= src_order:
        dst_order += 1
    second_action = (i // 5) % 6
    first_action = i % 5
    if first_action >= second_action:
        first_action += 1
    return G2Scheme(
        MUTATION_ORDER[src_order],
        MUTATION_ORDER[dst_order],
        PERMUTATIONS[first_action],
        PERMUTATIONS[second_action],
    )


HEADER_KEY = 0x8465B49B
ENTRY_CHUNK = 0x20000


def get_cstring(buf, off, max_end):
    end = buf.find(b'\x00', off, max_end)
    if end < 0:
        end = max_end
    return bytes(buf[off:end])


def parse_g2(path):
    with open(path, 'rb') as f:
        f.seek(0)
        raw_header = f.read(0x5C)
    if len(raw_header) != 0x5C:
        raise ValueError("文件过小, 无法读取 header")

    sch = make_scheme(HEADER_KEY)
    if sch is None:
        raise ValueError("HEADER scheme 构造失败")
    header = bytearray(0x5C)
    sch.decrypt(bytearray(raw_header), 0, header, 0, 0x5C)

    if bytes(header[:17]) != b'GLibArchiveData2.':
        raise ValueError(f"非 Glib2 包: 解密后 magic = {bytes(header[:18])!r}")
    if header[0x12] != 0:
        raise ValueError(f"header[0x12] != 0 (= {header[0x12]})")
    version = header[0x11] - ord('0')
    if version not in (0, 1):
        raise ValueError(f"未知 version: {version}")

    index_offset = struct.unpack_from('<I', header, 0x54)[0]
    index_size   = struct.unpack_from('<I', header, 0x58)[0]
    keys = [
        struct.unpack_from('<I', header, 0x44)[0],
        struct.unpack_from('<I', header, 0x34)[0],
        struct.unpack_from('<I', header, 0x24)[0],
        struct.unpack_from('<I', header, 0x14)[0],
    ]

    with open(path, 'rb') as f:
        f.seek(index_offset)
        enc_idx = f.read(index_size)
    if len(enc_idx) != index_size:
        raise ValueError("index 长度不足")

    # 4 层 ping-pong 解密
    bufA = bytearray(enc_idx)
    bufB = bytearray(index_size)
    cur_in, cur_out = bufA, bufB
    for k in keys:
        d = make_scheme(k)
        if d is None:
            raise ValueError(f"index key 0x{k:08X} 找不到 scheme hash")
        d.decrypt(cur_in, 0, cur_out, 0, index_size)
        cur_in, cur_out = cur_out, cur_in
    index = cur_in  # 最后写入的就是 cur_in

    if bytes(index[:4]) != b'CDBD':
        raise ValueError(f"index magic 错: {bytes(index[:4])!r}")

    count = struct.unpack_from('<i', index, 4)[0]
    info_base = 0x10 + struct.unpack_from('<i', index, 8)[0]
    names_base = 0x10 + count * 0x18

    entries = []
    cur = 0x10
    for i in range(count):
        name_off = names_base + struct.unpack_from('<i', index, cur)[0]
        parent_dir = struct.unpack_from('<i', index, cur + 8)[0]
        attr = struct.unpack_from('<i', index, cur + 0xC)[0]
        name = get_cstring(index, name_off, info_base).decode('cp932', errors='replace')
        if parent_dir != -1:
            parent_name = entries[parent_dir]['name']
            name = parent_name + '/' + name

        ent = {'name': name, 'attr': attr, 'parent': parent_dir,
               'is_file': attr == 0x100, 'offset': -1, 'size': 0,
               'keys': [0, 0, 0, 0]}
        if attr == 0x100:
            info_off = info_base + struct.unpack_from('<i', index, cur + 0x10)[0]
            ent['size']   = struct.unpack_from('<I', index, info_off + 8)[0]
            ent['offset'] = struct.unpack_from('<I', index, info_off + 0xC)[0]
            for j in range(4):
                info_off += 0x10
                ent['keys'][j] = struct.unpack_from('<I', index, info_off)[0]
        entries.append(ent)
        cur += 0x18

    return {
        'header': bytes(header),
        'raw_header': raw_header,
        'version': version,
        'index_offset': index_offset,
        'index_size': index_size,
        'keys': keys,
        'index': bytes(index),
        'entries': entries,
        'count': count,
        'info_base': info_base,
        'names_base': names_base,
    }


def extract_entry(path, ent):
    """读取 + 解密单个文件"""
    decoders = []
    offset = 0
    for j in range(4):
        if offset >= ent['size']:
            decoders.append(None)
            break
        d = make_scheme(ent['keys'][j])
        decoders.append(d)
        if d is not None:
            offset += ENTRY_CHUNK

    output = bytearray(ent['size'])
    with open(path, 'rb') as f:
        f.seek(ent['offset'])
        cur_dec = 0
        off = 0
        while off < ent['size']:
            chunk_size = min(ENTRY_CHUNK, ent['size'] - off)
            buf = f.read(chunk_size)
            if len(buf) != chunk_size:
                raise ValueError(f"读取 {ent['name']} 时数据不足")
            d = decoders[cur_dec] if cur_dec < len(decoders) else None
            if d is not None:
                d.decrypt(bytearray(buf), 0, output, off, chunk_size)
            else:
                output[off:off + chunk_size] = buf
            cur_dec = (cur_dec + 1) & 3
            off += chunk_size
    return bytes(output)


def main():
    ap = argparse.ArgumentParser(description="Glib2 .g2 解包器")
    sub = ap.add_subparsers(dest='cmd', required=True)
    pl = sub.add_parser('list', help="列出文件")
    pl.add_argument('input')
    pe = sub.add_parser('extract', help="解出全部文件")
    pe.add_argument('input')
    pe.add_argument('-o', '--output', default='extracted')
    pe.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    parsed = parse_g2(args.input)
    files = [e for e in parsed['entries'] if e['is_file'] and e['offset'] != 0xFFFFFFFF]

    if args.cmd == 'list':
        print(f"version={parsed['version']}  index@0x{parsed['index_offset']:X}  "
              f"size=0x{parsed['index_size']:X}  count={parsed['count']}")
        for e in files:
            print(f"  off=0x{e['offset']:08X}  size={e['size']:>10}  {e['name']}")
        print(f"\ntotal files: {len(files)}")
        return

    os.makedirs(args.output, exist_ok=True)
    manifest = {
        'version': parsed['version'],
        'index_keys': parsed['keys'],
        'files': {},
    }
    for e in files:
        rel = e['name'].replace('\\', '/').lstrip('/')
        out_path = os.path.join(args.output, rel)
        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
        data = extract_entry(args.input, e)
        with open(out_path, 'wb') as f:
            f.write(data)
        manifest['files'][e['name']] = {
            'keys': e['keys'],
            'size': e['size'],
            'orig_offset': e['offset'],
        }
        if args.verbose:
            print(f"  {e['name']}  ({e['size']} B)")
    # 写 manifest (供封包器复用 keys)
    with open(os.path.join(args.output, '_manifest.json'), 'w', encoding='utf-8') as f:
        import json as _json
        _json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"\n解出 {len(files)} 个文件 -> {args.output}/")


if __name__ == '__main__':
    main()
