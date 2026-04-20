#!/usr/bin/env python3
"""
DAC 引擎 DPK 解包 / 封包工具
=============================

DPK (DAC Package) 是ペンギンワークス的 DAC 引擎所用的资源封包格式。
这个工具基于对 hentai.exe (へんたいイニシアチブ 2013) 的逆向 +
参考 GARbro (ArcDPK.cs) 源码完成。

文件结构 (全部 little-endian):
  [+0x00]  magic           = "DPK\0\0\0\0\0"  (8 字节明文)
  [+0x08]  header          8 字节, header[i] ^= (i-8)
           header[0..4]    = u32 data_offset (索引结束+数据开始的位置)
           header[4..8]    = u32 file_size (验证字段)
  [+0x10]  index           长度 = data_offset - 16, 链式 XOR 加密
           索引解密后:
             [+0] u32 count
             [+4] u32 offsets[count]  (每项相对 "4 + count*4")
             每个 entry:
               [+0]  u32 data_rel_offset  (相对 data_offset)
               [+4]  u32 size
               [+8]  u32 reserved (总是 0)
               [+c]  cp932 文件名 \0 结尾
  [+data_offset]  加密数据区 (每个 entry 独立加密)

加密:
  Header 解密:  header[i] ^= (byte)(i - 8)     → i=0..7, XOR 值 0xF8..0xFF
  
  Index 解密:  链式 XOR
    key = (base_offset + i + last_cipher_byte) & 0xff
    last_cipher_byte = buf[i]  (解密前)
    buf[i] ^= key
    (base_offset = 16, 即 index 在文件中的起始位置)
  
  Entry 解密: 流密码
    KEY1 = 0x71bd, KEY2 = 0x713e66eb  (引擎硬编码)
    hash = 0
    for c in name_bytes[::-1]:
        hash += KEY1 + KEY2 * (entry_size + c)    (mod 2^32)
    k1 = KEY1
    for i, byte in enumerate(data):
        sb = (k1 & 0xff) + ((k1 >> 8) & 0xff)
        plain[i] = ((byte ^ sb) - hash) & 0xff
        k1 += KEY2
    注意 name_bytes = basename(去掉扩展名末尾 'z') 的 cp932 编码.
"""
import os, sys, struct
from pathlib import Path

# ==== 常量 ====
MAGIC = b"DPK\x00\x00\x00\x00\x00"
KEY1  = 0x71bd
KEY2  = 0x713e66eb


# ==== 解密/加密原语 ====

def _crypt_header(buf8: bytearray) -> None:
    """Header 加密/解密是自反的 (XOR) — 同一个函数做两个方向。"""
    for i in range(8):
        buf8[i] ^= (i - 8) & 0xFF


def _decrypt_index(buf: bytearray, base_offset: int = 16) -> None:
    """链式 XOR 解密。last 初值 = 调用者传入 (header[7] 的密文值)。
    注意: 这个函数自己会维护 last = 原始 buf[i],
    调用者必须在 _crypt_header **之前** 保存 header[7]。
    """
    # last 需要由调用方传入 (header 解密前的 header[7])
    raise NotImplementedError("use _decrypt_index_with_last")


def _decrypt_index_with_last(buf: bytearray, base_offset: int, last: int) -> None:
    for i in range(len(buf)):
        k = (base_offset + i + last) & 0xFF
        last = buf[i]               # 用的是解密前的值
        buf[i] ^= k


def _encrypt_index(plain: bytearray, base_offset: int, last: int) -> None:
    """逆向 _decrypt_index_with_last。
    明文 → 密文: last 递推规律变了,
    因为 decrypt 里 last = 密文 (解密前 = buf[i] 原值), 而我们现在从 plain 生成 cipher.
      cipher[i] = plain[i] ^ (base + i + last_cipher)
      last_cipher = cipher[i]
    所以直接按这个公式一路推进即可。
    """
    for i in range(len(plain)):
        k = (base_offset + i + last) & 0xFF
        cipher_byte = plain[i] ^ k
        plain[i] = cipher_byte
        last = cipher_byte


def _compute_hash(name_bytes: bytes, entry_size: int) -> int:
    """per-entry hash, 返回 u32。实际使用时取 & 0xff。"""
    h = 0
    for i in range(len(name_bytes) - 1, -1, -1):
        h = (h + KEY1 + KEY2 * (entry_size + name_bytes[i])) & 0xFFFFFFFF
    return h


def _crypt_entry(data: bytearray, name_bytes: bytes, entry_size: int) -> None:
    """Entry 流密码, 加解密对称 (因为 XOR + 减/加 hash 互逆):
    解密: plain = (cipher ^ sb) - hash
    加密: cipher = (plain + hash) ^ sb
    
    但注意 XOR 和 +/- 不可交换, 两个方向要写成不同代码。
    这个函数做 "解密"; 加密用 _crypt_entry_encrypt。
    """
    h = _compute_hash(name_bytes, entry_size) & 0xFF
    k1 = KEY1
    for i in range(len(data)):
        sb = ((k1 & 0xFF) + ((k1 >> 8) & 0xFF)) & 0xFF
        data[i] = ((data[i] ^ sb) - h) & 0xFF
        k1 = (k1 + KEY2) & 0xFFFFFFFF


def _crypt_entry_encrypt(data: bytearray, name_bytes: bytes, entry_size: int) -> None:
    """加密: cipher = (plain + hash) ^ sb"""
    h = _compute_hash(name_bytes, entry_size) & 0xFF
    k1 = KEY1
    for i in range(len(data)):
        sb = ((k1 & 0xFF) + ((k1 >> 8) & 0xFF)) & 0xFF
        data[i] = (((data[i] + h) & 0xFF) ^ sb) & 0xFF
        k1 = (k1 + KEY2) & 0xFFFFFFFF


# ==== 名字处理 ====

def _name_bytes_for_hash(name_in_index: bytes) -> bytes:
    """从 index 里的原始文件名 (cp932) 得出 hash 用的 name_bytes:
       1. basename (去路径分隔符)
       2. 末尾若是 'z' 去掉 (dacz → dac)
    """
    # 去路径
    for sep in (b'/', b'\\'):
        i = name_in_index.rfind(sep)
        if i >= 0:
            name_in_index = name_in_index[i+1:]
    # 去尾 z
    if name_in_index and name_in_index[-1:] == b'z':
        name_in_index = name_in_index[:-1]
    return name_in_index


# ==== 解包 ====

class DpkEntry:
    __slots__ = ('name', 'data_rel_offset', 'size', 'reserved')
    def __init__(self, name: bytes, data_rel_offset: int, size: int, reserved: int = 0):
        self.name = name
        self.data_rel_offset = data_rel_offset
        self.size = size
        self.reserved = reserved


def parse_dpk(dpk_bytes: bytes):
    """解析 DPK 文件头 + 索引, 返回 (data_offset, entries_list)。"""
    if len(dpk_bytes) < 16 or dpk_bytes[:4] != b'DPK\x00':
        raise ValueError("不是合法的 DPK 文件 (magic 错误)")
    
    # Header
    header = bytearray(dpk_bytes[8:16])
    last_for_index = header[7]          # 保存!  在 _crypt_header 之前
    _crypt_header(header)
    data_offset = struct.unpack_from('<I', header, 0)[0]
    file_size_check = struct.unpack_from('<I', header, 4)[0]
    if data_offset <= 16 or data_offset >= len(dpk_bytes):
        raise ValueError(f"data_offset 0x{data_offset:x} 不合法")
    if file_size_check != len(dpk_bytes):
        print(f"[warning] header 中的 file_size (0x{file_size_check:x}) "
              f"与实际文件大小 (0x{len(dpk_bytes):x}) 不一致")
    
    # Index
    index_length = data_offset - 16
    index = bytearray(dpk_bytes[16:16+index_length])
    _decrypt_index_with_last(index, base_offset=16, last=last_for_index)
    
    count = struct.unpack_from('<I', index, 0)[0]
    if not (0 < count < 0xFFFFF):
        raise ValueError(f"count 不合理: {count}")
    
    entries_base = 4 + count * 4
    # 收集 (idx_in_offsets_table, rel_in_index) 用于确定物理顺序
    # 然后按 idx 顺序返回 entries; 另外返回一个 physical_order 列表,
    # 记录 "按物理顺序 第 k 项 是 idx[physical_order[k]]"
    rels = []
    for i in range(count):
        rel = struct.unpack_from('<I', index, 4 + i*4)[0]
        rels.append(rel)
    
    entries = []
    for i in range(count):
        rel = rels[i]
        idx_off = entries_base + rel
        if idx_off + 0x0c > index_length:
            raise ValueError(f"entry {i} 越界")
        data_rel = struct.unpack_from('<I', index, idx_off)[0]
        size     = struct.unpack_from('<I', index, idx_off + 4)[0]
        reserved = struct.unpack_from('<I', index, idx_off + 8)[0]
        ne = index.find(b'\x00', idx_off + 0x0c)
        if ne < 0:
            ne = index_length
        name = bytes(index[idx_off+0x0c:ne])
        entries.append(DpkEntry(name, data_rel, size, reserved))
    
    # physical_order[k] = i 表示 "物理排第 k 位的是 idx[i]"
    physical_order = sorted(range(count), key=lambda i: rels[i])
    
    return data_offset, entries, physical_order


def unpack(dpk_path: str, out_dir: str):
    """解包 dpk 到目录, 每个文件独立解密。
    同时生成 _order.txt 记录原始顺序 (封包时要保持一致)。
    格式: 每行 "<idx_order_pos>\t<physical_order_pos>\t<name>"
    其中 idx_order_pos = 该 entry 在 offset 表的位置 (决定 entry_no),
    physical_order_pos = 该 entry 在 index 物理布局的位置.
    """
    dpk = open(dpk_path, 'rb').read()
    data_offset, entries, physical_order = parse_dpk(dpk)
    
    os.makedirs(out_dir, exist_ok=True)
    print(f"[unpack] {dpk_path}: {len(entries)} 个文件, data@0x{data_offset:x}")
    
    # physical_pos[i] = 该 entry 在物理布局中的位置
    physical_pos = [0] * len(entries)
    for k, i in enumerate(physical_order):
        physical_pos[i] = k
    
    lines = []
    for i, e in enumerate(entries):
        off = data_offset + e.data_rel_offset
        enc = bytearray(dpk[off:off+e.size])
        nb = _name_bytes_for_hash(e.name)
        _crypt_entry(enc, nb, e.size)
        
        try:
            name_str = e.name.decode('cp932')
        except UnicodeDecodeError:
            name_str = e.name.decode('cp932', errors='replace')
        safe = name_str.replace('/', '_').replace('\\', '_')
        out_path = os.path.join(out_dir, safe)
        with open(out_path, 'wb') as f:
            f.write(enc)
        # 格式: idx_pos \t physical_pos_in_index \t data_rel_offset \t name
        lines.append(f"{i}\t{physical_pos[i]}\t{e.data_rel_offset}\t{name_str}")
    
    with open(os.path.join(out_dir, '_order.txt'), 'w', encoding='utf-8') as f:
        f.write("# idx_pos\tindex_physical_pos\tdata_rel_offset\tname\n")
        for line in lines:
            f.write(line + '\n')
    print(f"[unpack] done → {out_dir}")


# ==== 封包 ====

def pack(src_dir: str, dpk_path: str):
    """从目录重新封包为 DPK。
    _order.txt 格式 (新, 4 列, 以 \\t 分隔, # 开头为注释):
        idx_pos  index_physical_pos  data_rel_offset  name
    - idx_pos: 该 entry 在 offsets 表里的位置
    - index_physical_pos: 该 entry metadata 在索引区的物理排列位置
    - data_rel_offset: 该 entry 数据在 data 区的偏移 (为了 bit-perfect 保留原值)
    - name: 文件名 (cp932 可编码)
    
    兼容旧格式 (3 列: idx/physical/name, 无 data_rel_offset)
    以及最老格式 (1 列: name, 都按字母序). 两种情况下 data 区按 idx 顺序紧凑累加.
    """
    order_file = os.path.join(src_dir, '_order.txt')
    
    # 读入 order file
    names_by_idx = None
    physical_pos = None
    data_rel_override = None   # 若非 None, 每个 idx 对应的 data_rel_offset
    
    if os.path.exists(order_file):
        with open(order_file, 'r', encoding='utf-8') as f:
            raw_lines = [l.rstrip('\n\r') for l in f if l.strip() and not l.startswith('#')]
        
        first = raw_lines[0].split('\t') if raw_lines else []
        cols = len(first)
        
        if cols >= 4:
            # 新格式
            tmp = []
            for line in raw_lines:
                parts = line.split('\t', 3)
                tmp.append((int(parts[0]), int(parts[1]), int(parts[2]), parts[3]))
            tmp.sort(key=lambda x: x[0])
            names_by_idx = [t[3] for t in tmp]
            physical_pos = [t[1] for t in tmp]
            data_rel_override = [t[2] for t in tmp]
        elif cols == 3:
            tmp = []
            for line in raw_lines:
                a, b, c = line.split('\t', 2)
                tmp.append((int(a), int(b), c))
            tmp.sort(key=lambda x: x[0])
            names_by_idx = [t[2] for t in tmp]
            physical_pos = [t[1] for t in tmp]
        else:
            names_by_idx = raw_lines
            print("[pack] _order.txt 是旧格式, 不保证 bit-perfect round-trip")
    else:
        names_by_idx = sorted(
            n for n in os.listdir(src_dir)
            if not n.startswith('_') and os.path.isfile(os.path.join(src_dir, n))
        )
        print("[pack] 没有 _order.txt, 按字母序")
    
    count = len(names_by_idx)
    if physical_pos is None:
        physical_pos = list(range(count))
    
    # 读入明文
    items = []
    for n in names_by_idx:
        safe_disk = n.replace('/', '_').replace('\\', '_')
        fp = os.path.join(src_dir, safe_disk)
        data = open(fp, 'rb').read()
        try:
            name_cp932 = n.encode('cp932')
        except UnicodeEncodeError as e:
            raise ValueError(f"无法把文件名 {n!r} 编码为 cp932: {e}")
        nb = _name_bytes_for_hash(name_cp932)
        items.append((name_cp932, nb, data))
    
    entries_base = 4 + count * 4
    
    # data 区布局: 如果有 override 就用它 (保证 bit-perfect), 否则按 idx 顺序累加
    if data_rel_override is not None:
        data_offsets_by_idx = list(data_rel_override)
        # 计算 data 区总长度 (= max(offset + size))
        data_region_size = max(data_offsets_by_idx[i] + len(items[i][2]) for i in range(count))
    else:
        data_offsets_by_idx = [0] * count
        cur = 0
        for i, (_, _, d) in enumerate(items):
            data_offsets_by_idx[i] = cur
            cur += len(d)
        data_region_size = cur
    
    # index 里 entry metadata 的物理排列 (由 physical_pos 决定)
    physical_order = [0] * count   # physical_order[k] = idx i
    for i, k in enumerate(physical_pos):
        physical_order[k] = i
    
    entry_rel_offsets = [0] * count
    entry_blobs_physical = []
    cur_entry_off = 0
    for k in range(count):
        i = physical_order[k]
        name_cp932, _, data = items[i]
        entry_rel_offsets[i] = cur_entry_off
        blob = struct.pack('<III', data_offsets_by_idx[i], len(data), 0) + name_cp932 + b'\x00'
        entry_blobs_physical.append(blob)
        cur_entry_off += len(blob)
    
    index_length = entries_base + cur_entry_off
    data_offset = 16 + index_length
    
    # 构造索引明文
    index = bytearray(index_length)
    struct.pack_into('<I', index, 0, count)
    for i, rel in enumerate(entry_rel_offsets):
        struct.pack_into('<I', index, 4 + i*4, rel)
    cursor = entries_base
    for blob in entry_blobs_physical:
        index[cursor:cursor+len(blob)] = blob
        cursor += len(blob)
    
    # 构造 data 区: 每个 entry 根据 data_offsets_by_idx[i] 放入
    data_region = bytearray(data_region_size)
    for i, (name_cp932, nb, data) in enumerate(items):
        enc = bytearray(data)
        _crypt_entry_encrypt(enc, nb, len(data))
        off = data_offsets_by_idx[i]
        data_region[off:off+len(enc)] = enc
    
    total_file_size = 16 + index_length + len(data_region)
    
    header_plain = struct.pack('<II', data_offset, total_file_size)
    header = bytearray(header_plain)
    _crypt_header(header)
    last_for_index = header[7]
    
    _encrypt_index(index, base_offset=16, last=last_for_index)
    
    out = bytearray()
    out += MAGIC
    out += header
    out += index
    out += data_region
    
    with open(dpk_path, 'wb') as f:
        f.write(out)
    print(f"[pack] {dpk_path}: {count} 个文件, total 0x{len(out):x}")


# ==== CLI ====

def main():
    import argparse
    ap = argparse.ArgumentParser(description='DAC 引擎 DPK 封包工具 (for script.dpk/picture.dpk/...)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    
    ap_u = sub.add_parser('unpack', help='解包 DPK 到目录')
    ap_u.add_argument('dpk', help='输入 .dpk 文件')
    ap_u.add_argument('out', help='输出目录')
    
    ap_p = sub.add_parser('pack', help='把目录封包为 DPK')
    ap_p.add_argument('src', help='源目录 (含 _order.txt)')
    ap_p.add_argument('dpk', help='输出 .dpk 文件')
    
    ap_v = sub.add_parser('verify', help='round-trip 验证: unpack → pack → 比对')
    ap_v.add_argument('dpk', help='输入 .dpk 文件')
    
    ap_l = sub.add_parser('list', help='列出 DPK 内容')
    ap_l.add_argument('dpk', help='输入 .dpk 文件')
    
    args = ap.parse_args()
    
    if args.cmd == 'unpack':
        unpack(args.dpk, args.out)
    elif args.cmd == 'pack':
        pack(args.src, args.dpk)
    elif args.cmd == 'list':
        data = open(args.dpk,'rb').read()
        data_offset, entries, _ = parse_dpk(data)
        print(f"{args.dpk}: {len(entries)} entries, data @ 0x{data_offset:x}")
        for i, e in enumerate(entries):
            name = e.name.decode('cp932', errors='replace')
            print(f"  [{i:4}] @0x{e.data_rel_offset:08x} size=0x{e.size:08x}  {name}")
    elif args.cmd == 'verify':
        import tempfile, hashlib
        original = open(args.dpk,'rb').read()
        with tempfile.TemporaryDirectory() as td:
            out_dir = os.path.join(td, 'unpacked')
            new_dpk = os.path.join(td, 'rebuilt.dpk')
            unpack(args.dpk, out_dir)
            pack(out_dir, new_dpk)
            rebuilt = open(new_dpk,'rb').read()
        
        # MD5 比对
        md5_a = hashlib.md5(original).hexdigest()
        md5_b = hashlib.md5(rebuilt).hexdigest()
        print(f"\nOriginal size:  {len(original)}  md5 {md5_a}")
        print(f"Rebuilt  size:  {len(rebuilt)}  md5 {md5_b}")
        if md5_a == md5_b:
            print("*** ROUND-TRIP BIT-PERFECT ***")
        else:
            # 找第一个 diff
            n = min(len(original), len(rebuilt))
            for i in range(n):
                if original[i] != rebuilt[i]:
                    print(f"first diff @ 0x{i:x}: orig=0x{original[i]:02x} new=0x{rebuilt[i]:02x}")
                    break
            if len(original) != len(rebuilt):
                print(f"size diff: orig {len(original)}  new {len(rebuilt)}")

if __name__ == '__main__':
    main()
