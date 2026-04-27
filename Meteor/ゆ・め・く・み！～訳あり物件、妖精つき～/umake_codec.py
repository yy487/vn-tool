# -*- coding: utf-8 -*-
"""
UMakeMe! / ARCHIVE engine DAT codec
Adv1.exe (アトリエかぐや?) 系 / 实际来自 EXE 逆向:
  - 静态密钥: b"UMakeMe!"     (PTR_s_UMakeMe__00488bec)
  - magic:    b"ARCHIVE"       (s_ARCHIVE_00488c60)

文件结构 (从 FUN_0041ca00 逆向):
  [0x00..0x11]  随机/未使用 (seek SET 0x11)
  [0x11..0x19]  8B  filekey_enc   -> filekey = enc XOR "UMakeMe!"
                (seek CUR +5)
  [0x1E..0x42]  36B header_enc    -> header  = enc XOR filekey (i=0..35, key[i&7])
      [0..16]   "ARCHIVE\0..."
      [16..20]  index_offset  (相对 0x1E)
      [20..32]  保留 12B (观察值为 14010000 + 8B 00)
      [32..36]  entry_count
  数据区 / 索引表都在 0x1E 之后 (index_offset + 0x1E)
  整个 [0x1E..文件末]   连续 XOR 流, 字节 i 使用 key[i & 7]

索引表 (entry_count × 0x114 字节):
  [0x000]       flag (观察=0)
  [0x001..0x100] 文件名 (C-string, CP932)
  [0x100..0x108] 8B 保留 (观察前4字节=0x4B/0x85 类型标志, 后4=0)
  [0x108..0x10C] data_offset (相对 0x1E)
  [0x10C..0x110] data_size
  [0x110..0x114] 尾部 u32 (观察=0)

数据本体同样用 filekey 循环 XOR (下标 = 文件相对 0x1E 的偏移).
"""
import struct

STATIC_KEY = b"UMakeMe!"   # 8 字节
HEADER_BASE = 0x1E          # 所有相对偏移的基准
HEADER_SIZE = 0x24          # 36B
ENTRY_SIZE  = 0x114         # 276B
MAGIC       = b"ARCHIVE"


def derive_filekey(raw: bytes) -> bytes:
    """从文件 [0x11..0x19] 解出 8B filekey."""
    if len(raw) < 0x19:
        raise ValueError("file too small")
    enc = raw[0x11:0x19]
    return bytes(a ^ b for a, b in zip(enc, STATIC_KEY))


def xor_stream(buf: bytes, key: bytes, stream_index: int) -> bytes:
    """对 buf 做 XOR, 下标从 stream_index 开始 (key 长度必须为 8).
    stream_index 是该 buf 第一个字节在"XOR 流"中的位置
    (= 该字节 file_offset - HEADER_BASE).
    """
    return bytes(b ^ key[(stream_index + i) & 7] for i, b in enumerate(buf))


def parse_header(raw: bytes, filekey: bytes):
    enc = raw[HEADER_BASE:HEADER_BASE + HEADER_SIZE]
    dec = xor_stream(enc, filekey, 0)
    if not dec.startswith(MAGIC):
        raise ValueError(f"bad magic: {dec[:16]!r}")
    index_off = struct.unpack_from('<I', dec, 16)[0]
    mid12     = dec[20:32]
    entry_cnt = struct.unpack_from('<I', dec, 32)[0]
    return {
        'index_off_rel': index_off,
        'index_off_abs': index_off + HEADER_BASE,
        'mid12'        : mid12,
        'entry_count'  : entry_cnt,
        'header_dec'   : dec,
    }


def parse_index(raw: bytes, filekey: bytes, info):
    entries, entry_cnt = [], info['entry_count']
    abs_off = info['index_off_abs']
    size    = entry_cnt * ENTRY_SIZE
    enc = raw[abs_off:abs_off + size]
    if len(enc) != size:
        raise ValueError(f"index truncated: {len(enc)}/{size}")
    dec = xor_stream(enc, filekey, info['index_off_rel'])
    for i in range(entry_cnt):
        e = dec[i*ENTRY_SIZE : (i+1)*ENTRY_SIZE]
        flag   = e[0]
        name   = e[1:0x100].split(b'\x00', 1)[0]
        tag8   = e[0x100:0x108]
        d_off  = struct.unpack_from('<I', e, 0x108)[0]
        d_size = struct.unpack_from('<I', e, 0x10C)[0]
        tail   = struct.unpack_from('<I', e, 0x110)[0]
        entries.append({
            'index': i,
            'flag' : flag,
            'name' : name,
            'tag8' : tag8,
            'off'  : d_off,
            'size' : d_size,
            'tail' : tail,
            'raw'  : e,          # 完整 276B 明文, 用于 repack 位保真
        })
    return entries, dec


def read_file_data(raw: bytes, filekey: bytes, entry) -> bytes:
    abs_off = entry['off'] + HEADER_BASE
    enc = raw[abs_off:abs_off + entry['size']]
    if len(enc) != entry['size']:
        raise ValueError(f"data truncated: {entry['name']}")
    return xor_stream(enc, filekey, entry['off'])


# ----- 打包方向 -----
def build_file(entries_in, filekey: bytes,
               header_plain: bytes,
               pre17: bytes,
               pad5: bytes) -> bytes:
    """
    entries_in: [(entry_raw_276B_plain, data_bytes), ...]
        entry_raw_276B_plain 是解包时保存的完整 276B 明文条目.
        data 尺寸可与原始不同 (变长注入); 此函数会自动重写
        [0x108] data_off 与 [0x10C] data_size, 其它字段位保真保留.
    header_plain: 原始 36B header 明文. 此函数会重写 [16..20] index_off,
        其它字段 (包括 magic/保留/entry_count 相关区) 位保真保留.
        注意 entry_count 不会自动重算, 调用方如改变条目数要自己改 header_plain.
    pre17: 原始 [0..0x11] 17B.
    pad5 : 原始 [0x19..0x1E] 5B padding.
    """
    assert len(pre17) == 0x11
    assert len(pad5)  == 5
    assert len(header_plain) == HEADER_SIZE
    assert len(filekey) == 8

    out = bytearray()
    out += pre17
    out += bytes(a ^ b for a, b in zip(filekey, STATIC_KEY))   # filekey_enc
    out += pad5
    assert len(out) == HEADER_BASE

    # 预留 36B header (稍后回填加密结果)
    out += bytes(HEADER_SIZE)
    assert len(out) == HEADER_BASE + HEADER_SIZE

    # 写数据区
    patched_entries = []
    for raw_entry, data in entries_in:
        assert len(raw_entry) == ENTRY_SIZE
        d_off = len(out) - HEADER_BASE
        enc = xor_stream(data, filekey, d_off)
        out += enc
        # 写回条目 off/size
        ent = bytearray(raw_entry)
        struct.pack_into('<I', ent, 0x108, d_off)
        struct.pack_into('<I', ent, 0x10C, len(data))
        patched_entries.append(bytes(ent))

    # 索引表位置
    index_off_rel = len(out) - HEADER_BASE

    # 索引表明文拼接
    idx_plain = b''.join(patched_entries)
    # 加密并写出
    out += xor_stream(idx_plain, filekey, index_off_rel)

    # 回填 header (改写 [16..20] = index_off_rel, 其它保持)
    hp = bytearray(header_plain)
    struct.pack_into('<I', hp, 16, index_off_rel)
    header_enc = xor_stream(bytes(hp), filekey, 0)
    out[HEADER_BASE:HEADER_BASE+HEADER_SIZE] = header_enc

    return bytes(out)
