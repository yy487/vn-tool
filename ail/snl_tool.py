#!/usr/bin/env python3
"""
snl_tool.py v2 - AIL 引擎 .snl / .dat 容器格式工具

适用厂商: アイル (AIL / ail-soft.com)
样本文件: sall.snl / GALL*.DAT / PALL*.DAT / VALL*.DAT / THELP.DAT

============================================================
容器格式 (来自 Ghidra: FUN_00420130 + GARbro: ArcAil.cs)
============================================================

外层索引:
    [0]      u32   count           条目数 N
    [1..N]   u32   sizes[N]        每条原始字节数 (含内嵌header)
    [...]    bytes 紧密堆放,无对齐

每条目内嵌 header:
    [+0]  u16  flag            bit0=1 表示 LZSS 压缩
    [+2]  u32  unpacked_size   仅 packed 时有效
    [+6]  ...  payload         (压缩或未压数据)

特殊条目:
    flag==0 或 [+4]=='OggS' -> header 只有 4 字节,后面是裸数据
    sall.snl 里没有这类,GALL/VALL 等媒体封包里才会出现.

LZSS 算法见 ail_lzss.py.
"""

import os, sys, struct, json, argparse
from ail_lzss import compress as lzss_compress, decompress as lzss_decompress


def parse_entry_header(raw: bytes):
    if len(raw) < 6:
        return {'kind': 'plain6', 'payload': raw}
    sig = struct.unpack_from('<I', raw, 0)[0]
    flag = sig & 0xFFFF
    if flag == 1:
        unpacked = struct.unpack_from('<I', raw, 2)[0]
        return {'kind': 'packed', 'unpacked_size': unpacked, 'payload': raw[6:]}
    elif sig == 0 or raw[4:8] == b'OggS':
        return {'kind': 'plain4', 'payload': raw[4:]}
    else:
        return {'kind': 'plain6', 'payload': raw[6:]}


def read_container(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    count = struct.unpack_from('<I', data, 0)[0]
    sizes = list(struct.unpack_from(f'<{count}I', data, 4))
    return data, count, sizes, (1 + count) * 4


def unpack(snl_path: str, out_dir: str, decompress: bool = True):
    data, count, sizes, header_size = read_container(snl_path)
    os.makedirs(out_dir, exist_ok=True)
    offset = header_size
    manifest = {
        'mode': 'decompressed' if decompress else 'raw',
        'count': count,
        'entries': [],
    }

    for i, size in enumerate(sizes):
        raw = data[offset:offset + size]
        offset += size

        if size == 0:
            manifest['entries'].append({'id': i, 'kind': 'empty'})
            continue

        if decompress:
            hdr = parse_entry_header(raw)
            if hdr['kind'] == 'packed':
                payload = lzss_decompress(hdr['payload'], hdr['unpacked_size'])
            else:
                payload = hdr['payload']
            name = f'{i:04d}.bin'
            with open(os.path.join(out_dir, name), 'wb') as f:
                f.write(payload)
            manifest['entries'].append({
                'id': i, 'name': name, 'kind': hdr['kind'],
            })
        else:
            name = f'{i:04d}.raw'
            with open(os.path.join(out_dir, name), 'wb') as f:
                f.write(raw)
            manifest['entries'].append({
                'id': i, 'name': name, 'kind': 'raw',
            })

    with open(os.path.join(out_dir, '_manifest.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    nonempty = sum(1 for s in sizes if s > 0)
    print(f'[OK] 解包完成: {count} 条 ({nonempty} 非空, mode={manifest["mode"]}) -> {out_dir}')


def pack(in_dir: str, out_path: str):
    with open(os.path.join(in_dir, '_manifest.json'), 'r', encoding='utf-8') as f:
        manifest = json.load(f)

    count = manifest['count']
    mode = manifest['mode']

    sizes, blobs = [], []
    for e in manifest['entries']:
        if e['kind'] == 'empty':
            sizes.append(0); blobs.append(b'')
            continue
        with open(os.path.join(in_dir, e['name']), 'rb') as f:
            payload = f.read()

        if mode == 'raw':
            full = payload
        elif e['kind'] == 'packed':
            comp = lzss_compress(payload)
            full = struct.pack('<HI', 0x0001, len(payload)) + comp
        elif e['kind'] == 'plain4':
            full = b'\x00\x00\x00\x00' + payload
        elif e['kind'] == 'plain6':
            # Standard uncompressed AIL entry: u16 flag=0 + u32 size + payload.
            full = struct.pack('<HI', 0x0000, len(payload)) + payload
        else:
            raise NotImplementedError(f'kind={e["kind"]} 需要 raw 模式')

        sizes.append(len(full)); blobs.append(full)

    with open(out_path, 'wb') as f:
        f.write(struct.pack('<I', count))
        f.write(struct.pack(f'<{count}I', *sizes))
        for b in blobs:
            f.write(b)
    print(f'[OK] 封包完成: {count} 条 (mode={mode}) -> {out_path}')


def info(snl_path: str):
    data, count, sizes, header_size = read_container(snl_path)
    stats = {'packed': 0, 'plain4': 0, 'plain6': 0, 'empty': 0}
    total_unpacked = 0
    offset = header_size
    for sz in sizes:
        if sz == 0:
            stats['empty'] += 1; continue
        raw = data[offset:offset + sz]; offset += sz
        hdr = parse_entry_header(raw)
        stats[hdr['kind']] += 1
        if hdr['kind'] == 'packed':
            total_unpacked += hdr['unpacked_size']
        else:
            total_unpacked += len(hdr['payload'])

    print(f'文件: {snl_path}')
    print(f'大小: {len(data)} (0x{len(data):x})')
    print(f'条目数: {count}  (header {header_size}B + 数据 {sum(sizes)}B)')
    print(f'校验:   {"OK" if header_size + sum(sizes) == len(data) else "FAIL"}')
    print(f'条目分类:')
    for k, v in stats.items():
        if v: print(f'  {k:10}: {v}')
    print(f'解压后总大小: {total_unpacked} 字节 (压缩比 {sum(sizes)/total_unpacked:.3f})')


def main():
    ap = argparse.ArgumentParser(description='AIL .snl/.dat 容器工具 v2')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('unpack')
    p1.add_argument('snl')
    p1.add_argument('-o', '--out', default='snl_out')
    p1.add_argument('--raw', action='store_true', help='保留原始压缩态')

    p2 = sub.add_parser('pack')
    p2.add_argument('dir')
    p2.add_argument('-o', '--out', default='sall_new.snl')

    p3 = sub.add_parser('info')
    p3.add_argument('snl')

    args = ap.parse_args()
    if args.cmd == 'unpack':
        unpack(args.snl, args.out, decompress=not args.raw)
    elif args.cmd == 'pack':
        pack(args.dir, args.out)
    elif args.cmd == 'info':
        info(args.snl)


if __name__ == '__main__':
    main()
