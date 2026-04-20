# -*- coding: utf-8 -*-
"""
GSX1 (.fbx) 文本注入器 — ペンギンワークス Love Caba 引擎

策略: 全量重建字符串池
  1. 读原始 .fbx + 翻译 JSON
  2. 重建字符串池(相同原文共享槽位)
  3. 回填 TABLE_A.str_off 和 TABLE_C bit0=1 条目的 str_off
  4. 重算 Header 中 3 个表的 offset
  5. 写出新 .fbx

不变量:
  - TABLE_B 完全不变
  - TABLE_A/C 条数和结构不变,只改 str_off 字段
  - Header 中 ta_raw/tb_raw/tc_raw 不变(表自身大小不变)
"""
import struct, json, os, sys

MAGIC = 0x31585347


def parse_header(data):
    mg, ver, so, sz, ta_off, ta_raw, tb_off, tb_raw, tc_off, tc_raw = \
        struct.unpack_from('<10I', data, 0)
    if mg != MAGIC:
        raise ValueError(f'bad magic {mg:#x}')
    return dict(version=ver, str_off=so, str_size=sz,
                ta_off=ta_off, ta_raw=ta_raw, ta_count=ta_raw >> 4,
                tb_off=tb_off, tb_raw=tb_raw, tb_count=tb_raw >> 3,
                tc_off=tc_off, tc_raw=tc_raw, tc_count=tc_raw >> 3)


def load_translations(json_path):
    if not json_path or not os.path.exists(json_path):
        return {}
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get('translations') or data.get('data') or list(data.values())
    tr = {}
    for it in data:
        if not isinstance(it, dict):
            continue
        msg = it.get('message') or it.get('jp') or it.get('src') or it.get('original')
        dst = (it.get('translation') or it.get('trans') or it.get('pre_translation') or
               it.get('post_jp') or it.get('new') or it.get('cn') or it.get('zh'))
        if msg and dst and msg != dst:
            tr[msg] = dst
    return tr


def inject(fbx_path, json_path, out_path, target_codec='gbk'):
    with open(fbx_path, 'rb') as f:
        data = f.read()
    h = parse_header(data)
    tr = load_translations(json_path)
    print(f'\n=== inject {os.path.basename(fbx_path)} ===')
    print(f'  translations loaded: {len(tr)}')

    # 读原池
    pool = data[h['str_off']:h['str_off'] + h['str_size']]

    def read_at(off):
        if off < 0 or off >= h['str_size']:
            return None
        end = pool.index(b'\x00', off)
        try:
            return pool[off:end].decode('cp932'), pool[off:end]
        except UnicodeDecodeError:
            return None, pool[off:end]

    # 收集所有引用
    ta_refs = []
    for i in range(h['ta_count']):
        so = struct.unpack_from('<i', data, h['ta_off'] + i * 16 + 4)[0]
        ta_refs.append((i, so))

    tc_refs = []
    for i in range(h['tc_count']):
        off = h['tc_off'] + i * 8
        if data[off] & 1 == 0:
            continue
        so = struct.unpack_from('<i', data, off + 4)[0]
        tc_refs.append((i, so))

    all_offs = set(so for _, so in ta_refs if so != -1 and 0 <= so < h['str_size'])
    all_offs |= set(so for _, so in tc_refs if so != -1 and 0 <= so < h['str_size'])
    print(f'  TABLE_A refs: {len(ta_refs)}  TABLE_C refs: {len(tc_refs)}  '
          f'unique offsets: {len(all_offs)}')

    # 重建池: 按原 offset 升序,相同编码字节共享槽位
    new_pool = bytearray()
    old2new = {-1: -1}
    dedup = {}
    n_tr = n_fail = 0
    fails = []

    for old_off in sorted(all_offs):
        res = read_at(old_off)
        if res is None:
            continue
        s, raw_bytes = res
        if s is None:
            # 解码失败,原样保留
            encoded = raw_bytes
        else:
            cn = tr.get(s)
            if cn:
                try:
                    encoded = cn.encode(target_codec)
                    n_tr += 1
                except UnicodeEncodeError as e:
                    n_fail += 1
                    if len(fails) < 5:
                        fails.append((s, cn, str(e)))
                    encoded = s.encode('cp932')
            else:
                encoded = s.encode('cp932')

        if encoded in dedup:
            old2new[old_off] = dedup[encoded]
        else:
            new_off = len(new_pool)
            new_pool.extend(encoded)
            new_pool.append(0)
            old2new[old_off] = new_off
            dedup[encoded] = new_off

    new_sz = len(new_pool)
    # 4 字节对齐
    pad = (-new_sz) & 3
    new_pool.extend(b'\x00' * pad)
    print(f'  new pool: {new_sz:#x} (+pad {pad}) vs orig {h["str_size"]:#x}  '
          f'diff {len(new_pool) - h["str_size"]:+d}')
    print(f'  translated applied: {n_tr}')
    if n_fail:
        print(f'  !! {target_codec} encode failures: {n_fail}')
        for jp, cn, err in fails:
            print(f'     {jp!r} → {cn!r}  [{err}]')

    # 重建表 A 和 C
    new_ta = bytearray(data[h['ta_off']:h['ta_off'] + h['ta_count'] * 16])
    for i, old in ta_refs:
        struct.pack_into('<i', new_ta, i * 16 + 4, old2new.get(old, old))

    new_tc = bytearray(data[h['tc_off']:h['tc_off'] + h['tc_count'] * 8])
    for i, old in tc_refs:
        struct.pack_into('<i', new_tc, i * 8 + 4, old2new.get(old, old))

    new_tb = data[h['tb_off']:h['tb_off'] + h['tb_count'] * 8]

    # 组装
    s_off = 0x28
    a_off = s_off + len(new_pool)
    b_off = a_off + len(new_ta)
    c_off = b_off + len(new_tb)

    header = struct.pack('<10I', MAGIC, h['version'],
                         s_off, new_sz,
                         a_off, h['ta_raw'],
                         b_off, h['tb_raw'],
                         c_off, h['tc_raw'])

    out = header + bytes(new_pool) + bytes(new_ta) + bytes(new_tb) + bytes(new_tc)
    print(f'  new file: {len(out):#x} vs orig {len(data):#x}  diff {len(out) - len(data):+d}')

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or '.', exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(out)
    print(f'  → {out_path}')
    return out


def verify(new_path):
    with open(new_path, 'rb') as f:
        data = f.read()
    h = parse_header(data)
    pool = data[h['str_off']:h['str_off'] + h['str_size']]
    starts = {0}
    for i, b in enumerate(pool):
        if b == 0 and i + 1 < len(pool):
            starts.add(i + 1)
    n_ref = n_bad = 0
    for i in range(h['tc_count']):
        off = h['tc_off'] + i * 8
        if data[off] & 1 == 0: continue
        n_ref += 1
        so = struct.unpack_from('<i', data, off + 4)[0]
        if so == -1: continue
        if so not in starts:
            n_bad += 1
    n_ta_bad = 0
    for i in range(h['ta_count']):
        so = struct.unpack_from('<i', data, h['ta_off'] + i * 16 + 4)[0]
        if so == -1: continue
        if so not in starts:
            n_ta_bad += 1
    status = 'OK' if (n_bad == 0 and n_ta_bad == 0) else 'FAIL'
    print(f'[verify {os.path.basename(new_path)}] tc_refs={n_ref} tc_bad={n_bad} '
          f'ta_bad={n_ta_bad}  {status}')
    return n_bad == 0 and n_ta_bad == 0


def roundtrip(fbx_path):
    """空翻译回写自测。"""
    print(f'\n=== round-trip (no translation) {os.path.basename(fbx_path)} ===')
    out = os.path.join('/tmp', os.path.basename(fbx_path) + '.rt.tmp')
    inject(fbx_path, None, out, target_codec='gbk')
    ok = verify(out)
    # 额外:比较提取内容是否等价
    import gsx1_extract as ex
    h1 = ex.parse_header(open(fbx_path, 'rb').read())
    h2 = ex.parse_header(open(out, 'rb').read())
    # 简单等价:TABLE_A 和 TABLE_C 中每个引用处解出的字符串序列必须完全相同
    def dump_refs(path):
        d = open(path, 'rb').read()
        hh = ex.parse_header(d)
        base = hh['str_off']
        pool = d[base:base + hh['str_size']]
        out = []
        for i in range(hh['ta_count']):
            so = struct.unpack_from('<i', d, hh['ta_off'] + i * 16 + 4)[0]
            if so == -1:
                out.append(('TA', i, None)); continue
            e = pool.index(b'\x00', so)
            out.append(('TA', i, pool[so:e]))
        for i in range(hh['tc_count']):
            off = hh['tc_off'] + i * 8
            if d[off] & 1 == 0: continue
            so = struct.unpack_from('<i', d, off + 4)[0]
            if so == -1:
                out.append(('TC', i, None)); continue
            e = pool.index(b'\x00', so)
            out.append(('TC', i, pool[so:e]))
        return out

    a = dump_refs(fbx_path)
    b = dump_refs(out)
    if a == b:
        print(f'[roundtrip] 所有引用解出字符串完全一致 ({len(a)} 条)  OK')
    else:
        diff = sum(1 for x, y in zip(a, b) if x != y)
        print(f'[roundtrip] MISMATCH  diffs={diff}/{len(a)}')
        for (x, y) in zip(a, b):
            if x != y:
                print(f'   orig: {x}')
                print(f'   new : {y}')
                break
    os.remove(out)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('用法:')
        print('  python gsx1_inject.py <in.fbx> [trans.json] [out.fbx]')
        print('  python gsx1_inject.py --roundtrip <in.fbx>')
        sys.exit(1)

    if sys.argv[1] == '--roundtrip':
        roundtrip(sys.argv[2])
        sys.exit(0)

    in_fbx = sys.argv[1]
    tr_json = sys.argv[2] if len(sys.argv) > 2 else None
    out_fbx = sys.argv[3] if len(sys.argv) > 3 else \
              os.path.splitext(in_fbx)[0] + '.cn.fbx'

    inject(in_fbx, tr_json, out_fbx, target_codec='gbk')
    verify(out_fbx)
