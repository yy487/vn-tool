#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdvSystem .ac2 归档 解包/封包工具
引擎：AdvSystem (LostPassage 及同族)

格式（小端）:
  Header (12B):
    u32 entry_count
    u32 unknown (=0x0C)
    u32 data_base_offset   (= 12 + count*100)

  Index: count × 100 字节, 每个条目独立加密 (nibble swap + NOT)
  条目解密后 100 字节:
    [0x00:0x40] filename (CP932, C string)
    [0x40:0x44] packed_size
    [0x44:0x48] offset (相对 data_base)
    [0x48:0x4C] flag  (0=raw, 1=LZSS)
    [0x4C:0x50] unpacked_size
    [0x50:0x64] timestamp "YYYY/MM/DD HH:MM:SS\0"

  Data: raw 或 LZSS (4KB window, init 0xFEE, LSB-first flag, min match 3)

用法:
  解包:   python ac2_tool.py unpack  Data.ac2  out_dir/
  封包:   python ac2_tool.py repack  in_dir/   Data.ac2  [--manifest manifest.json]
  列表:   python ac2_tool.py list    Data.ac2

封包策略:
  - 默认读取 unpack 时生成的 manifest.json 保留 flag/时间戳
  - 无 manifest 时：全部以 raw (flag=0) 封入，时间戳用当前时间
  - 不做 LZSS 压缩 (引擎支持 flag=0 raw 路径，零风险)
"""

import os, sys, struct, json, argparse, datetime

ENTRY_SIZE   = 100
HEADER_SIZE  = 12
MAGIC_UNK    = 0x0C
NAME_LEN     = 0x40
TS_LEN       = 20
TS_FMT       = '%Y/%m/%d %H:%M:%S'

# ---------- 加密 ----------
def _dec_byte(x): return (~(((x >> 4) & 0x0F) | ((x << 4) & 0xF0))) & 0xFF
_ENC_TABLE = bytes(_dec_byte(i) for i in range(256))  # 对合: dec == enc
def crypt(buf): return bytes(_ENC_TABLE[b] for b in buf)

# ---------- LZSS ----------
def lzss_decompress(data, unpacked_size):
    window = bytearray(4096)
    out = bytearray()
    w_pos = 0xFEE
    src = 0
    flags = 0
    n = len(data)
    while len(out) < unpacked_size and src < n:
        flags >>= 1
        if (flags & 0x100) == 0:
            flags = data[src] | 0xFF00
            src += 1
            if src >= n and len(out) >= unpacked_size: break
        if flags & 1:
            if src >= n: break
            b = data[src]; src += 1
            out.append(b)
            window[w_pos] = b
            w_pos = (w_pos + 1) & 0xFFF
        else:
            if src + 1 >= n: break
            lo = data[src]; hi = data[src+1]; src += 2
            offset = lo | ((hi & 0xF0) << 4)
            length = (hi & 0x0F) + 3
            for _ in range(length):
                b = window[offset & 0xFFF]
                out.append(b)
                window[w_pos] = b
                w_pos = (w_pos + 1) & 0xFFF
                offset += 1
                if len(out) >= unpacked_size: break
    return bytes(out[:unpacked_size])

# ---------- 条目结构 ----------
def parse_entry(raw100):
    e = crypt(raw100)
    name = e[:NAME_LEN].split(b'\x00', 1)[0].decode('cp932', errors='replace')
    packed   = struct.unpack_from('<I', e, 0x40)[0]
    offset   = struct.unpack_from('<I', e, 0x44)[0]
    flag     = struct.unpack_from('<I', e, 0x48)[0]
    unpacked = struct.unpack_from('<I', e, 0x4C)[0]
    ts       = e[0x50:0x50+TS_LEN].split(b'\x00', 1)[0].decode('cp932', errors='replace')
    return dict(name=name, packed=packed, offset=offset, flag=flag,
                unpacked=unpacked, ts=ts)

def build_entry(name, packed, offset, flag, unpacked, ts):
    buf = bytearray(ENTRY_SIZE)
    nb = name.encode('cp932')
    if len(nb) >= NAME_LEN:
        raise ValueError(f'文件名过长 (>{NAME_LEN-1}B): {name}')
    buf[:len(nb)] = nb
    struct.pack_into('<IIII', buf, 0x40, packed, offset, flag, unpacked)
    tb = ts.encode('cp932')
    if len(tb) > TS_LEN: tb = tb[:TS_LEN]
    buf[0x50:0x50+len(tb)] = tb
    return crypt(bytes(buf))

# ---------- 高层操作 ----------
def read_header(f):
    hdr = f.read(HEADER_SIZE)
    if len(hdr) != HEADER_SIZE:
        raise ValueError('文件过小，无 header')
    count, unk, data_base = struct.unpack('<III', hdr)
    if unk != MAGIC_UNK:
        print(f'[warn] header 第二字段 != 0x0C (读到 0x{unk:X})')
    expect = HEADER_SIZE + count * ENTRY_SIZE
    if data_base != expect:
        print(f'[warn] data_base 0x{data_base:X} != 预期 0x{expect:X}')
    return count, unk, data_base

def list_entries(ac2_path):
    with open(ac2_path, 'rb') as f:
        count, unk, data_base = read_header(f)
        print(f'Count={count}  Unk=0x{unk:X}  DataBase=0x{data_base:X}')
        for i in range(count):
            e = parse_entry(f.read(ENTRY_SIZE))
            abs_off = data_base + e['offset']
            print(f'  [{i:3d}] {e["name"]:40s} pk={e["packed"]:8d} up={e["unpacked"]:8d} '
                  f'flag={e["flag"]} off=0x{abs_off:08X} ts={e["ts"]}')

def unpack(ac2_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    manifest = {'entries': []}
    with open(ac2_path, 'rb') as f:
        count, unk, data_base = read_header(f)
        manifest['unknown'] = unk
        entries = [parse_entry(f.read(ENTRY_SIZE)) for _ in range(count)]
        for i, e in enumerate(entries):
            f.seek(data_base + e['offset'])
            raw = f.read(e['packed'])
            if e['flag'] == 1:
                data = lzss_decompress(raw, e['unpacked'])
            elif e['flag'] == 0:
                data = raw
            else:
                print(f'[warn] [{i}] 未知 flag={e["flag"]}, 按 raw 导出')
                data = raw
            if len(data) != e['unpacked']:
                print(f'[warn] [{i}] {e["name"]}: unpacked_size {e["unpacked"]} 实得 {len(data)}')
            # 展开到文件系统路径 (反斜杠 -> 系统分隔符)
            rel = e['name'].replace('\\', os.sep)
            out_path = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
            with open(out_path, 'wb') as g:
                g.write(data)
            manifest['entries'].append({
                'index': i,
                'name':  e['name'],
                'flag':  e['flag'],
                'ts':    e['ts'],
            })
            if (i+1) % 20 == 0 or i == count-1:
                print(f'  [{i+1}/{count}] {e["name"]}')
    mpath = os.path.join(out_dir, 'manifest.json')
    with open(mpath, 'w', encoding='utf-8') as g:
        json.dump(manifest, g, ensure_ascii=False, indent=2)
    print(f'OK: {count} 个文件 -> {out_dir}')
    print(f'manifest: {mpath}')

def repack(in_dir, out_ac2, manifest_path=None):
    # 读 manifest
    if manifest_path is None:
        mp = os.path.join(in_dir, 'manifest.json')
        if os.path.exists(mp):
            manifest_path = mp

    if manifest_path and os.path.exists(manifest_path):
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        raw_entries = manifest['entries']
        raw_entries.sort(key=lambda x: x.get('index', 0))
        print(f'[info] 使用 manifest: {manifest_path} ({len(raw_entries)} 条目)')
    else:
        # 无 manifest: 扫描目录
        print('[info] 无 manifest, 扫描目录生成条目列表 (全 flag=0)')
        raw_entries = []
        for root, _, files in os.walk(in_dir):
            for fn in files:
                if fn == 'manifest.json': continue
                full = os.path.join(root, fn)
                rel  = os.path.relpath(full, in_dir).replace(os.sep, '\\')
                raw_entries.append({'name': rel, 'flag': 0,
                                    'ts': datetime.datetime.now().strftime(TS_FMT)})
        raw_entries.sort(key=lambda x: x['name'])

    # 加载所有数据, 决定打包策略
    # 若 flag=1 但我们没有 LZSS 压缩器, 强制改为 flag=0 (raw)

    # 路径自动探测: 尝试两种模式
    #   ① in_dir + name                  (正常: name=DATA\SCRIPT\xxx, in_dir=父目录)
    #   ② in_dir + basename(name)         (去掉name路径前缀)
    #   ③ parent(in_dir) + name           (in_dir 多了一层前缀)
    # 以第一条能找到的策略为准
    first_name = raw_entries[0]['name']
    candidates = [
        lambda n: os.path.join(in_dir, n.replace('\\', os.sep)),
        # 去 manifest name 的首级目录: DATA\SCRIPT\xxx -> SCRIPT\xxx
        lambda n: os.path.join(in_dir,
                               os.sep.join(n.replace('\\', os.sep).split(os.sep)[1:])),
    ]
    resolver = None
    for c in candidates:
        if os.path.exists(c(first_name)):
            resolver = c
            break
    if resolver is None:
        raise FileNotFoundError(
            f'无法定位首个文件 {first_name}\n'
            f'  尝试 1: {candidates[0](first_name)}\n'
            f'  尝试 2: {candidates[1](first_name)}\n'
            f'请确认 in_dir 是否正确'
        )
    if resolver is not candidates[0]:
        print(f'[info] 路径模式: 跳过 name 的首级目录 (in_dir 已是其父)')

    packed_entries = []
    for m in raw_entries:
        name = m['name']
        rel_path = resolver(name)
        if not os.path.exists(rel_path):
            raise FileNotFoundError(f'缺失文件: {rel_path}')
        with open(rel_path, 'rb') as f:
            data = f.read()
        flag = 0  # 强制 raw, 引擎原生支持 flag=0
        packed_entries.append(dict(name=name, data=data, flag=flag,
                                   unpacked=len(data), packed=len(data),
                                   ts=m.get('ts', datetime.datetime.now().strftime(TS_FMT))))

    count = len(packed_entries)
    data_base = HEADER_SIZE + count * ENTRY_SIZE

    # 分配 offset
    cur = 0
    for e in packed_entries:
        e['offset'] = cur
        cur += e['packed']

    # 写
    with open(out_ac2, 'wb') as g:
        g.write(struct.pack('<III', count, MAGIC_UNK, data_base))
        for e in packed_entries:
            g.write(build_entry(e['name'], e['packed'], e['offset'],
                                e['flag'], e['unpacked'], e['ts']))
        for e in packed_entries:
            g.write(e['data'])

    total = os.path.getsize(out_ac2)
    print(f'OK: {count} 条目 -> {out_ac2} ({total:,} 字节)')
    print(f'[note] 所有条目以 flag=0 (raw) 封入, 引擎原生支持')

# ---------- 自检 ----------
def selftest(ac2_path, tmp_dir):
    """解包 -> 封包 -> 再解包, 对比内容一致"""
    import hashlib, shutil
    d1 = os.path.join(tmp_dir, 'round1')
    d2 = os.path.join(tmp_dir, 'round2')
    ac2b = os.path.join(tmp_dir, 'round1.ac2')
    for d in (d1, d2):
        if os.path.exists(d): shutil.rmtree(d)
    print('=== round1: unpack 原文件 ===')
    unpack(ac2_path, d1)
    print('=== round2: repack ===')
    repack(d1, ac2b)
    print('=== round3: 再 unpack ===')
    unpack(ac2b, d2)
    # 对比
    ok, bad = 0, 0
    for root, _, files in os.walk(d1):
        for fn in files:
            if fn == 'manifest.json': continue
            a = os.path.join(root, fn)
            rel = os.path.relpath(a, d1)
            b = os.path.join(d2, rel)
            da = open(a,'rb').read()
            db = open(b,'rb').read()
            if da == db: ok += 1
            else:
                bad += 1
                print(f'  [DIFF] {rel}: {len(da)} vs {len(db)}')
    print(f'一致: {ok}  不一致: {bad}')
    return bad == 0

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description='AdvSystem .ac2 解包/封包')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('list');   p.add_argument('ac2')
    p = sub.add_parser('unpack'); p.add_argument('ac2'); p.add_argument('out_dir')
    p = sub.add_parser('repack'); p.add_argument('in_dir'); p.add_argument('ac2')
    p.add_argument('--manifest', default=None)
    p = sub.add_parser('selftest'); p.add_argument('ac2'); p.add_argument('tmp_dir')

    args = ap.parse_args()
    if   args.cmd == 'list':   list_entries(args.ac2)
    elif args.cmd == 'unpack': unpack(args.ac2, args.out_dir)
    elif args.cmd == 'repack': repack(args.in_dir, args.ac2, args.manifest)
    elif args.cmd == 'selftest': sys.exit(0 if selftest(args.ac2, args.tmp_dir) else 1)

if __name__ == '__main__':
    main()
