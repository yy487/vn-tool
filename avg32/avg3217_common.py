#!/usr/bin/env python3
"""
avg3217_common.py — AVG3217 引擎公共库 (v4, 正确处理子脚本结构)

关键发现 (修 v3 的崩溃):
  TPC32 不是一整块字节码, 而是多个独立子脚本:
    - 头 0x20: magic + cc
    - [0x20 .. tail_start]: cc*4 字节未知表
    - [tail_start .. tail_start+0x30]: metadata (包括 n_e_scripts, n_var_groups)
    - [tail_start+0x30 .. ...]: 变量表区 (pascal 字符串 + 嵌套结构)
    - 然后是 4 类子脚本, 每个带 u32 len 前缀:
        A 子脚本 (1 个)
        B 子脚本 (1 个)
        C 子脚本 (1 个)
        e[] 子脚本数组 (n_e_scripts 个, 最常见的主剧情脚本)

  跳转 u32 是**相对所在子脚本起点**的偏移, 不是 tail_start!
  因此:
    1. 每个子脚本独立扫跳转/文本
    2. 每个子脚本独立做 delta 修正
    3. 子脚本加长时, 其**前面的 u32 len 字段必须同步更新**
    4. 同一 plain 里其它子脚本位置自动平移 (不需要额外处理, VM 加载时动态重算)
"""
import struct


# ============== PACK LZSS ==============

def pack_decompress(blk):
    assert blk[:4] == b'PACK', f'not PACK: {blk[:8]!r}'
    ucsize = struct.unpack_from('<I', blk, 8)[0]
    csize  = struct.unpack_from('<I', blk, 12)[0]
    out = bytearray()
    src = 16
    ctrl = 0; bits = 0
    while src < csize and len(out) < ucsize:
        if bits == 0:
            ctrl = blk[src]; src += 1; bits = 8
            continue
        if ctrl & 0x80:
            out.append(blk[src]); src += 1
        else:
            if src + 1 >= len(blk): break
            word = struct.unpack_from('<H', blk, src)[0]
            src += 2
            offset = (word >> 4) + 1
            length = (word & 0xF) + 2
            base = len(out) - offset
            for i in range(length):
                out.append(out[base + i] if base + i >= 0 else 0)
        ctrl = (ctrl << 1) & 0xFF
        bits -= 1
    return bytes(out)


def pack_compress(plain):
    out = bytearray()
    n = len(plain)
    p = 0
    while p < n:
        out.append(0xFF)
        out.extend(plain[p:p+8])
        p += 8
    csize = 16 + len(out)
    return b'PACK\0\0\0\0' + struct.pack('<II', n, csize) + bytes(out)


# ============== PACL 容器 ==============

def pacl_unpack(data):
    assert data[:4] == b'PACL', 'not PACL'
    count = struct.unpack_from('<I', data, 16)[0]
    items = []
    for i in range(count):
        eoff = 32 + i * 32
        name = data[eoff:eoff+16].rstrip(b'\0').decode('latin1')
        a, csize, ucsize, flag = struct.unpack_from('<4I', data, eoff+16)
        items.append((name, csize, ucsize, flag, data[a:a+csize]))
    return items


def pacl_repack(items):
    n = len(items)
    out = bytearray(b'PACL' + b'\0'*12)
    out += struct.pack('<I', n) + b'\0'*12
    idx_start = len(out)
    out += b'\0' * (n * 32)
    for i, (name, blk, ucsize, flag) in enumerate(items):
        offset = len(out)
        csize = len(blk)
        eoff = idx_start + i * 32
        name_b = name.encode('latin1')[:16]
        name_b += b'\0' * (16 - len(name_b))
        out[eoff:eoff+16] = name_b
        struct.pack_into('<4I', out, eoff+16, offset, csize, ucsize, flag)
        out += blk
    return bytes(out)


# ============== TPC32 完整结构解析 ==============

def parse_tpc32(plain):
    """完整解析 TPC32 文件. 返回:
    {
      'cc': int,                    # header @0x18
      'tail_start': int,            # = 0x20 + cc*4
      'metadata': {...},
      'var_table_end': int,
      'subscripts': [{'name', 'len_off', 'start', 'length'}, ...]
    }
    """
    assert plain[:5] == b'TPC32', f'not TPC32: {plain[:8]!r}'
    cc = struct.unpack_from('<I', plain, 0x18)[0]
    tail_start = 0x20 + cc * 4
    
    md = {
        'n_e_scripts': struct.unpack_from('<I', plain, tail_start + 0x08)[0],
        'n_var_groups': struct.unpack_from('<I', plain, tail_start + 0x0C)[0],
        'var_iv3': struct.unpack_from('<I', plain, tail_start + 0x24)[0],
        'var_iv4': struct.unpack_from('<I', plain, tail_start + 0x28)[0],
    }
    
    # 解析变量表 (第 1 段: 嵌套计数结构)
    pb = tail_start + 0x30
    sub_counts = []
    for i in range(md['n_var_groups']):
        var_id = plain[pb]
        sub_count = plain[pb+1]
        pb += 2
        sub_counts.append(sub_count)
        for j in range(sub_count):
            entry_id = plain[pb]
            sub2_count = plain[pb+1]
            pb += 2
            for k in range(sub2_count):
                inner_count = plain[pb]
                pb += 1
                pb += inner_count * 3
    
    # 第 2 段: pascal 字符串 (变量名)
    for i in range(md['n_var_groups']):
        ln = plain[pb]
        pb += 1 + ln
        for j in range(sub_counts[i]):
            ln2 = plain[pb]
            pb += 1 + ln2
    
    var_table_end = pb
    
    # 解析子脚本: A, B, C, e0, e1, ...
    subscripts = []
    def read_one(name, cur):
        ln = struct.unpack_from('<I', plain, cur)[0]
        sub = {
            'name': name,
            'len_off': cur,
            'start': cur + 4,
            'length': ln,
        }
        return sub, cur + 4 + ln
    
    for tag in ['A', 'B', 'C']:
        sub, pb = read_one(tag, pb)
        subscripts.append(sub)
    for i in range(md['n_e_scripts']):
        sub, pb = read_one(f'e{i}', pb)
        subscripts.append(sub)
    
    return {
        'cc': cc,
        'tail_start': tail_start,
        'metadata': md,
        'var_table_end': var_table_end,
        'subscripts': subscripts,
    }


# ============== 合法 opcode 集合 ==============

LEGAL_OPCODES = frozenset([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x0B, 0x0C, 0x0E, 0x10, 0x13,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x20,
    0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31,
    0x37, 0x39, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
    0x56, 0x57, 0x58, 0x59, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x72, 0x73, 0x74, 0x75, 0x76, 0x7F,
    0xFE, 0xFF,
])


# ============== VarInt / 条件表达式 ==============

def varint_width(data, p):
    if p >= len(data): return 1
    b1 = data[p]
    return max(1, (b1 & 0x70) >> 4)


def parse_cond_expr(data, start):
    if start >= len(data):
        return None
    p = start
    if data[p] != 0x28:
        return p + 1
    depth = 0
    while p < len(data):
        c = data[p]
        if c == 0x28:
            depth += 1; p += 1
        elif c == 0x29:
            depth -= 1; p += 1
            if depth == 0: return p
        elif c in (0x26, 0x27):
            p += 1
        elif 0x36 <= c <= 0x55:
            p += 1
            p += varint_width(data, p)
            p += varint_width(data, p)
        else:
            p += 1
    return None


# ============== 子脚本内部文本 op 识别 ==============

def _is_text_payload_ok(sjis_bytes):
    if len(sjis_bytes) < 1:
        return False
    try:
        s = sjis_bytes.decode('cp932')
    except UnicodeDecodeError:
        return False
    if '\ufffd' in s:
        return False
    for c in s:
        co = ord(c)
        if co < 0x20 and c not in '\n\r\t':
            return False
        if 0xf8f0 <= co <= 0xf8ff:
            return False
    return True


def find_text_ops_in_subscript(plain, sub, *, line_max=10000):
    start = sub['start']
    end = start + sub['length']
    results = []
    p = start
    while p < end - 5:
        op = plain[p]
        if op == 0xFF or op == 0xFE:
            line = struct.unpack_from('<I', plain, p+1)[0]
            if line < line_max:
                eow = p + 5
                while eow < end and plain[eow] != 0:
                    eow += 1
                sjis = bytes(plain[p+5:eow])
                if _is_text_payload_ok(sjis):
                    results.append({
                        'op': op, 'off': p, 'line': line,
                        'text_off': p + 5, 'text_len': eow - (p + 5),
                        'sub_name': sub['name'],
                    })
                    p = eow + 1
                    continue
        p += 1
    return results


# ============== 子脚本内部跳转 op 识别 ==============

def find_jump_ops_in_subscript(plain, sub):
    """跳转 u32 相对子脚本起点 (不是 tail_start)."""
    start = sub['start']
    end = start + sub['length']
    
    def target_is_valid(abs_target):
        if not (start <= abs_target < end):
            return False
        return plain[abs_target] in LEGAL_OPCODES
    
    result = []
    p = start
    while p < end:
        op = plain[p]
        
        if op == 0x1C or op == 0x1B:
            if p + 5 <= end:
                u32 = struct.unpack_from('<I', plain, p+1)[0]
                abs_target = start + u32
                if target_is_valid(abs_target):
                    result.append({
                        'kind': 'goto' if op == 0x1C else 'gosub',
                        'op_off': p, 'u32_off': p+1,
                        'target': abs_target, 'target_rel': u32,
                        'sub_name': sub['name'],
                    })
        
        elif op == 0x15:
            expr_end = parse_cond_expr(plain, p+1)
            if expr_end is not None and expr_end + 4 <= end:
                u32 = struct.unpack_from('<I', plain, expr_end)[0]
                abs_target = start + u32
                if target_is_valid(abs_target):
                    result.append({
                        'kind': 'cond', 'op_off': p,
                        'u32_off': expr_end,
                        'target': abs_target, 'target_rel': u32,
                        'sub_name': sub['name'],
                    })
        
        elif op == 0x1D or op == 0x1E:
            if p + 2 < end:
                count = plain[p+1]
                if 1 <= count <= 32:
                    w = varint_width(plain, p+2)
                    jt_start = p + 2 + w
                    if jt_start + count * 4 <= end:
                        cand = []
                        all_ok = True
                        for i in range(count):
                            t_off = jt_start + i * 4
                            u32 = struct.unpack_from('<I', plain, t_off)[0]
                            abs_target = start + u32
                            if not target_is_valid(abs_target):
                                all_ok = False; break
                            cand.append((t_off, abs_target, u32))
                        if all_ok:
                            for t_off, abs_t, u32 in cand:
                                result.append({
                                    'kind': 'select', 'op_off': p,
                                    'u32_off': t_off,
                                    'target': abs_t, 'target_rel': u32,
                                    'sub_name': sub['name'],
                                })
        
        p += 1
    
    seen = {}
    deduped = []
    for j in result:
        if j['u32_off'] not in seen:
            seen[j['u32_off']] = j
            deduped.append(j)
    return deduped


# ============== 文件级别 API ==============

def find_all_text_ops(plain, info=None):
    if info is None:
        info = parse_tpc32(plain)
    result = []
    for sub in info['subscripts']:
        result.extend(find_text_ops_in_subscript(plain, sub))
    return result


def find_all_jump_ops(plain, info=None):
    if info is None:
        info = parse_tpc32(plain)
    result = []
    for sub in info['subscripts']:
        result.extend(find_jump_ops_in_subscript(plain, sub))
    return result


# ============== 注入: 子脚本感知的修正 ==============

def apply_fixups(plain, info, jumps, edits):
    """子脚本感知的 delta 修正.
    
    步骤:
      1. 按 edit 所在子脚本分组
      2. 每个子脚本独立算 delta, 修自身 jumps 的 u32
      3. 修每个子脚本前的 u32 len
      4. 倒序 splice edits
    """
    p = bytearray(plain)
    subs = info['subscripts']
    
    def locate_sub(off):
        for s in subs:
            if s['start'] <= off < s['start'] + s['length']:
                return s
        return None
    
    edits_by_sub = {}
    for e in edits:
        s = locate_sub(e['off'])
        if s is None:
            raise RuntimeError(f'edit @0x{e["off"]:X} 不在任何子脚本内')
        edits_by_sub.setdefault(s['name'], []).append(e)
    
    jumps_by_sub = {}
    for j in jumps:
        jumps_by_sub.setdefault(j['sub_name'], []).append(j)
    
    # 为每个子脚本修 jumps
    for sub in subs:
        sub_edits = edits_by_sub.get(sub['name'], [])
        sub_jumps = jumps_by_sub.get(sub['name'], [])
        if not sub_edits:
            continue
        
        sorted_edits = sorted(sub_edits, key=lambda x: x['off'])
        prefix = []
        cum = 0
        for e in sorted_edits:
            cum += len(e['new_bytes']) - e['orig_len']
            prefix.append((e['off'], cum))
        
        def delta_at(abs_pos, prefix=prefix):
            lo, hi = 0, len(prefix)
            while lo < hi:
                mid = (lo + hi) // 2
                if prefix[mid][0] < abs_pos:
                    lo = mid + 1
                else:
                    hi = mid
            return prefix[lo-1][1] if lo > 0 else 0
        
        for j in sub_jumps:
            delta = delta_at(j['target'])
            if delta != 0:
                old_u32 = struct.unpack_from('<I', p, j['u32_off'])[0]
                new_u32 = old_u32 + delta
                struct.pack_into('<I', p, j['u32_off'], new_u32)
    
    # 修子脚本 u32 len
    for sub in subs:
        sub_edits = edits_by_sub.get(sub['name'], [])
        total_delta = sum(len(e['new_bytes']) - e['orig_len'] for e in sub_edits)
        if total_delta != 0:
            new_len = sub['length'] + total_delta
            struct.pack_into('<I', p, sub['len_off'], new_len)
    
    # 倒序 splice
    sorted_all = sorted(edits, key=lambda e: e['off'], reverse=True)
    for e in sorted_all:
        off = e['off']
        orig_len = e['orig_len']
        new_bytes = e['new_bytes']
        p[off:off+orig_len] = new_bytes
    
    return bytes(p)


# ============== 向后兼容 API ==============

def parse_tpc32_header(plain):
    """向后兼容. 返回 (cc, tail_start, placeholder)"""
    info = parse_tpc32(plain)
    ce = [struct.unpack_from('<I', plain, 0x20 + i*4)[0] for i in range(info['cc'])]
    return info['cc'], info['tail_start'], ce


def find_text_ops(plain, tail_start=None, code_entries=None):
    return find_all_text_ops(plain)


def find_jump_ops(plain, tail_start=None, code_entries=None):
    return find_all_jump_ops(plain)
