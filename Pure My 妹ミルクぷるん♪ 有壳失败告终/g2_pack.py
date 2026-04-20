#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
g2_pack.py - Glib2 .g2 / .stx 资源包封包器
配合 g2_unpack.py 使用 (共享 hashes.txt + permutation 实现)

封包策略:
  - 完全重建 .g2: header (0x5C) + 文件数据区 + index
  - 文件名/层级结构: 从输入目录扫描得到 (与原包独立)
  - 文件 chunk keys: 优先复用 manifest.json (g2_unpack 会同时输出); 否则用固定默认 key
  - header 加密 key: 必须 0x8465B49B (引擎硬编码)
  - index 4 把 key: 优先复用 manifest; 否则随机但合法 (即必须是 PERMUTATION_HASHES 命中的 key)

加密公式 (推导自源码 G2Scheme.Decrypt 的逆):
  decrypt: out[base + dst_o[i&3]] = second(i, first(i, in[base + src_o[i&3]]))
  encrypt: out[base + src_o[i&3]] = first_inv(i, second_inv(i, in[base + dst_o[i&3]]))
  即 src/dst 角色互换 + perm 用逆函数

用法:
    # 1. 解包同时产出 manifest:
    python g2_unpack.py extract orig.g2 -o files/   (新增 manifest 输出)
    # 2. 修改 files/ 下的内容
    # 3. 封包:
    python g2_pack.py files/ -o new.g2 [--manifest files/_manifest.json]
"""
import os
import sys
import json
import struct
import argparse
import random

# 复用 unpack 的常量与原始函数
from g2_unpack import (
    PERMUTATIONS, MUTATION_ORDER, PERMUTATION_HASHES,
    rot_byte_l, rot_byte_r, make_scheme, G2Scheme,
    HEADER_KEY, ENTRY_CHUNK,
)


# ============================================================
# 逆 permutation
# ============================================================
INVERSE_PERMUTATIONS = [
    lambda i, x: rot_byte_l(x & 0xFF, i),       # inv of rot_byte_r
    lambda i, x: (x ^ i) & 0xFF,                # self-inverse
    lambda i, x: (~x) & 0xFF,                   # self-inverse
    lambda i, x: ((~x) + 100) & 0xFF,           # inv of ~(x-100)
    lambda i, x: (x - i) & 0xFF,                # inv of x+i
    lambda i, x: rot_byte_r(x & 0xFF, 4),       # inv of rot_byte_l(x,4) (self)
]


def _find_perm_index(f):
    for i, p in enumerate(PERMUTATIONS):
        if p is f:
            return i
    raise ValueError("perm not in table (scheme 不是 make_scheme 产出的)")


# ============================================================
# G2 加密 (encrypt = decrypt 的逆)
# ============================================================
def g2_encrypt(scheme, plain, p_off, cipher, c_off, length):
    """plain[base + dst_o[i&3]] -> cipher[base + src_o[i&3]]
       使用 first_inv(second_inv(plain[dst])) 计算 cipher[src]
       
       不对齐尾部 (<4B): 不重排, 直接 perm
    """
    fi_idx = _find_perm_index(scheme.first)
    si_idx = _find_perm_index(scheme.second)
    fi_inv = INVERSE_PERMUTATIONS[fi_idx]
    si_inv = INVERSE_PERMUTATIONS[si_idx]

    src_o = scheme.src_order
    dst_o = scheme.dst_order
    i = 0
    end_aligned = length & ~3
    while i < end_aligned:
        c_idx = c_off + (i & ~3) + src_o[i & 3]
        p_idx = p_off + (i & ~3) + dst_o[i & 3]
        v = si_inv(i, plain[p_idx])
        v = fi_inv(i, v)
        cipher[c_idx] = v
        i += 1
    # 尾部
    while i < length:
        v = si_inv(i, plain[p_off + i])
        v = fi_inv(i, v)
        cipher[c_off + i] = v
        i += 1


# ============================================================
# 选择合法 key (用于新生成的 chunk / index key)
# ============================================================
# 反查表: PermutationHashes 里有的 hash, 对应至少一把可用 key
# 但加密时我们其实可以直接用解包时拿到的原 key, 不用反查
def _is_valid_key(key):
    h = ((key * 0x5F) >> 13) & 0xFFFF
    return h in _hash_set


_hash_set = set(PERMUTATION_HASHES)


def find_default_key():
    """找一把简单的、合法的 key 作为默认 (新增文件时用)"""
    # 暴力搜小数字范围内的合法 key
    for k in range(0x100, 0x100000):
        if _is_valid_key(k):
            return k
    raise RuntimeError("找不到合法 key")


# ============================================================
# 重建 index
# ============================================================
def build_index(file_entries):
    """file_entries: [{'name': '...', 'parent': -1 或父索引, 'is_file': bool,
                       'size': int, 'offset': int, 'keys': [4 个 u32], 'attr': int}]
       
       order 必须是: 先列出根目录 (parent=-1), 再按层次列子项
       (parent 字段是该数组中的索引, 引用必须先于使用)
       
       返回 (index_bytes, total_size)
    """
    count = len(file_entries)
    file_count = sum(1 for e in file_entries if e['is_file'])

    # names 段: 紧密排列的 cstring (CP932)
    name_bytes_list = []
    name_offsets = []
    cur = 0
    for e in file_entries:
        # 取 basename (不含父路径前缀, 因为 parent_dir 已经表达了层级)
        # 简单处理: 名字就是 basename
        bn = os.path.basename(e['name'].replace('\\', '/').rstrip('/'))
        nb = bn.encode('cp932') + b'\x00'
        name_offsets.append(cur)
        name_bytes_list.append(nb)
        cur += len(nb)
    names_blob = b''.join(name_bytes_list)

    # 计算 layout
    HDR = 0x10
    DIR_ENTRY = 0x18
    INFO_BLOCK = 0x50

    names_base = HDR + count * DIR_ENTRY
    info_base = names_base + len(names_blob)
    total_size = info_base + file_count * INFO_BLOCK

    out = bytearray(total_size)
    # header: "CDBD" + count + (info_base - 0x10) + ?(=total_size? 待确认)
    out[0:4] = b'CDBD'
    struct.pack_into('<i', out, 4, count)
    struct.pack_into('<i', out, 8, info_base - HDR)
    # idx[12:16]: 原文件是 1520 = 0x5F0 = file_count(19) * 0x50 = info 区总大小
    struct.pack_into('<i', out, 12, file_count * INFO_BLOCK)

    # dir 条目
    file_idx = 0  # 当前文件 index, 用于计算 info_offset
    for i, e in enumerate(file_entries):
        cur_off = HDR + i * DIR_ENTRY
        struct.pack_into('<i', out, cur_off + 0x00, name_offsets[i])
        struct.pack_into('<i', out, cur_off + 0x04, 0)
        struct.pack_into('<i', out, cur_off + 0x08, e['parent'])
        struct.pack_into('<i', out, cur_off + 0x0C, e.get('attr',
                          0x100 if e['is_file'] else -1))
        if e['is_file']:
            struct.pack_into('<i', out, cur_off + 0x10, file_idx * INFO_BLOCK)
            struct.pack_into('<i', out, cur_off + 0x14, INFO_BLOCK)  # 0x50

            # info 块 (0x50B)
            info_off = info_base + file_idx * INFO_BLOCK
            # +0x00: 0x4C (常量)
            struct.pack_into('<I', out, info_off + 0x00, 0x4C)
            # +0x04: 0
            struct.pack_into('<I', out, info_off + 0x04, 0)
            # +0x08: size
            struct.pack_into('<I', out, info_off + 0x08, e['size'])
            # +0x0C: offset
            struct.pack_into('<I', out, info_off + 0x0C, e['offset'])
            # +0x10/+0x20/+0x30/+0x40: 4 把 key (后 12 个字节填 0)
            for j in range(4):
                struct.pack_into('<I', out, info_off + 0x10 + j * 0x10, e['keys'][j])
                # 后 12 字节本就是 0 (bytearray 初始化)
            file_idx += 1
        else:
            # 目录: info_offset = 0, info_block_size = 0
            struct.pack_into('<i', out, cur_off + 0x10, 0)
            struct.pack_into('<i', out, cur_off + 0x14, 0)

    # names 段
    out[names_base:names_base + len(names_blob)] = names_blob

    return bytes(out)


# ============================================================
# 加密 index (4 层 ping-pong, 顺序与解包相反: keys[3] -> keys[2] -> keys[1] -> keys[0]
# 解包是  keys[0]->[1]->[2]->[3] (Decrypt 调用顺序)
# 因此封包要从最后一把往回加密)
# ============================================================
def encrypt_index(plain_index, keys):
    """keys 是从 header 中读出的 4 把 key, 顺序与解包用的一样"""
    size = len(plain_index)
    # 为了让"最终密文用 keys[0] 解密能进入下一层", 我们要反向加密:
    #   解包: bufA = enc; for k in keys: decrypt(bufIn, bufOut, k); ping-pong
    #         结果是 bufA -> (k0) -> bufB -> (k1) -> bufA -> (k2) -> bufB -> (k3) -> bufA
    #         最终 plain 在 bufA (因为 4 次后 ping-pong 回到 A)
    #   封包: 反过来, plain 在 bufA, encrypt(k3), encrypt(k2), encrypt(k1), encrypt(k0)
    #         同样 ping-pong 4 次回到 bufA
    bufA = bytearray(plain_index)
    bufB = bytearray(size)
    cur_in, cur_out = bufA, bufB
    for k in reversed(keys):
        sch = make_scheme(k)
        if sch is None:
            raise ValueError(f"key 0x{k:08X} 不命中合法 hash")
        g2_encrypt(sch, cur_in, 0, cur_out, 0, size)
        cur_in, cur_out = cur_out, cur_in
    return bytes(cur_in)


# ============================================================
# 加密文件数据 (chunk 化)
# ============================================================
def encrypt_entry(plain_data, keys):
    """与 unpack/extract_entry 对应:
       - 把 plain 切成 ENTRY_CHUNK 块
       - 第 j 个 chunk 用 keys[j&3] 加密 (不命中 hash 的 key 不加密)
    """
    size = len(plain_data)
    out = bytearray(size)
    # 准备 4 个 scheme (与 unpack 完全相同的逻辑)
    decoders = []
    off = 0
    for j in range(4):
        if off >= size:
            decoders.append(None)
            break
        d = make_scheme(keys[j])
        decoders.append(d)
        if d is not None:
            off += ENTRY_CHUNK
    while len(decoders) < 4:
        decoders.append(None)

    cur = 0
    chunk_id = 0
    while cur < size:
        n = min(ENTRY_CHUNK, size - cur)
        d = decoders[chunk_id & 3]
        if d is not None:
            g2_encrypt(d, plain_data, cur, out, cur, n)
        else:
            out[cur:cur + n] = plain_data[cur:cur + n]
        chunk_id += 1
        cur += n
    return bytes(out)


# ============================================================
# 加密 header
# ============================================================
def build_and_encrypt_header(version, index_offset, index_size, keys):
    """返回 0x5C 字节加密后的 header"""
    plain = bytearray(0x5C)
    magic = b'GLibArchiveData2.'  # 17B
    plain[0:17] = magic
    plain[0x11] = ord('0') + version  # version digit
    plain[0x12] = 0
    # 4 把 key (注意源码读取顺序: header[0x44]=k0, [0x34]=k1, [0x24]=k2, [0x14]=k3)
    struct.pack_into('<I', plain, 0x14, keys[3])
    struct.pack_into('<I', plain, 0x24, keys[2])
    struct.pack_into('<I', plain, 0x34, keys[1])
    struct.pack_into('<I', plain, 0x44, keys[0])
    struct.pack_into('<I', plain, 0x54, index_offset)
    struct.pack_into('<I', plain, 0x58, index_size)

    sch = make_scheme(HEADER_KEY)
    cipher = bytearray(0x5C)
    g2_encrypt(sch, plain, 0, cipher, 0, 0x5C)
    return bytes(cipher)


# ============================================================
# 主流程: 打包目录 -> .g2
# ============================================================
def pack_dir_to_g2(input_dir, out_path, manifest=None, version=1):
    """input_dir: 解包后的目录 (扁平或带子目录)
       manifest: 来自 g2_unpack 的 _manifest.json (含原 keys, 用于 round-trip)
    """
    # 1. 先加载 manifest (用于排序 + key 复用)
    manifest_data = None
    if manifest and os.path.exists(manifest):
        with open(manifest, 'r', encoding='utf-8') as f:
            manifest_data = json.load(f)

    # 2. 收集所有文件 (递归)
    file_list = []
    for root, dirs, files in os.walk(input_dir):
        for fn in files:
            if fn == '_manifest.json':
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, input_dir).replace('\\', '/')
            file_list.append(rel)

    # 按 manifest 中的 orig_offset 排序 (用于 round-trip 字节一致);
    # 没有 manifest 或新增文件的, 排在末尾按字母序
    if manifest_data and 'files' in manifest_data:
        offset_map = {k.lstrip('/'): v.get('orig_offset', 0xFFFFFFFF)
                      for k, v in manifest_data['files'].items()}
        file_list.sort(key=lambda r: (offset_map.get(os.path.basename(r), 0xFFFFFFFF), r))
    else:
        file_list.sort()
    if not file_list:
        raise ValueError(f"目录 {input_dir} 下没有可封包的文件")

    # 2. 构建 entries: 先放根目录 ('', parent=-1, attr=-1), 再放所有文件 (parent=0)
    #    (TODO: 多级子目录处理 - 当前只支持单层根目录, 与你给的 scenario.g2 一致)
    entries = []
    # 根目录
    entries.append({
        'name': '',
        'parent': -1,
        'is_file': False,
        'attr': -1,
    })
    # 所有文件挂到根目录 (entries[0])
    # 如果有子目录, 这里需要递归先创建目录条目 - 暂不实现, 因为典型 .g2 都是扁平
    for rel in file_list:
        if '/' in rel:
            print(f"  [warn] 含子目录的文件 {rel} 暂不完整支持, 当作扁平文件处理")
        entries.append({
            'name': '/' + os.path.basename(rel),  # 引擎里看到的名字格式
            'parent': 0,
            'is_file': True,
            'rel_path': rel,  # 物理文件相对路径
        })

    # manifest_data: {'index_keys': [4 个 u32], 'files': {'/01COMMON.BCS': {'keys': [4 个 u32]}}}
    if manifest_data:
        index_keys = manifest_data.get('index_keys')
    else:
        index_keys = None

    if not index_keys:
        # 找一组合法 key
        default_k = find_default_key()
        index_keys = [default_k] * 4
        print(f"  [info] 无 manifest, 用默认 index keys: {[hex(k) for k in index_keys]}")

    default_chunk_key = find_default_key()

    # 4. 给每个文件分配 chunk keys
    for e in entries:
        if not e['is_file']:
            continue
        if manifest_data and e['name'] in manifest_data.get('files', {}):
            e['keys'] = manifest_data['files'][e['name']]['keys']
        else:
            # 新增文件: 用默认 key
            e['keys'] = [default_chunk_key] * 4

    # 5. 读取并加密所有文件数据, 决定 file_offset
    #    布局: [header 0x5C] [file1 data] [file2 data] ... [index]
    #    file_offset 必须从 0x5C 开始
    cur_offset = 0x5C
    encrypted_data_list = []
    for e in entries:
        if not e['is_file']:
            continue
        full = os.path.join(input_dir, e['rel_path'])
        with open(full, 'rb') as f:
            plain = f.read()
        e['size'] = len(plain)
        e['offset'] = cur_offset
        enc = encrypt_entry(plain, e['keys'])
        encrypted_data_list.append(enc)
        cur_offset += len(enc)

    # 6. 构建 + 加密 index
    plain_index = build_index(entries)
    enc_index = encrypt_index(plain_index, index_keys)
    index_offset = cur_offset
    index_size = len(enc_index)

    # 7. 构建 header
    enc_header = build_and_encrypt_header(version, index_offset, index_size, index_keys)

    # 8. 写文件
    with open(out_path, 'wb') as f:
        f.write(enc_header)
        for blob in encrypted_data_list:
            f.write(blob)
        f.write(enc_index)

    return {
        'file_count': sum(1 for e in entries if e['is_file']),
        'total_size': cur_offset + index_size,
        'index_offset': index_offset,
        'index_size': index_size,
    }


# ============================================================
# 主入口
# ============================================================
def main():
    ap = argparse.ArgumentParser(description="Glib2 .g2 封包器")
    ap.add_argument('input_dir', help="包含所有要打包文件的目录 (g2_unpack 解出的)")
    ap.add_argument('-o', '--output', required=True, help="输出 .g2 文件路径")
    ap.add_argument('--manifest', help="原始 _manifest.json (复用 keys, 用于 round-trip)")
    ap.add_argument('--version', type=int, default=1, choices=[0, 1])
    args = ap.parse_args()

    info = pack_dir_to_g2(args.input_dir, args.output, args.manifest, args.version)
    print(f"[OK]  {args.output}")
    print(f"      files={info['file_count']}  total={info['total_size']} B  "
          f"index@0x{info['index_offset']:X} size=0x{info['index_size']:X}")


if __name__ == '__main__':
    main()
