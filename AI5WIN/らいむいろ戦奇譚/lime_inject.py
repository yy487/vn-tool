#!/usr/bin/env python3
"""
AI5WIN v2 MES 文本注入工具
输入: LZSS压缩的原始MES + 翻译JSON
输出: LZSS压缩的MES (伪压缩, 全literal)

内部流程: LZSS解压 → 变长文本替换+偏移修正 → LZSS伪压缩

用法:
  python lime_inject.py <original.mes> <translated.json> [output.mes]
  python lime_inject.py <mes_dir> <json_dir> <output_dir>  (批量)

批量模式: 非MES文件和无对应JSON的MES文件直接原样复制
"""
import struct, json, sys, os

# ── LZSS ──
def lzss_decompress(src):
    window = bytearray(0x1000); wp = 0xFEE; out = bytearray()
    sp = 0; end = len(src); flags = 0; fb = 0
    while sp < end:
        if fb == 0: flags = src[sp]; sp += 1; fb = 8
        if flags & 1:
            if sp >= end: break
            b = src[sp]; sp += 1; out.append(b); window[wp] = b; wp = (wp+1)&0xFFF
        else:
            if sp+1 >= end: break
            lo = src[sp]; hi = src[sp+1]; sp += 2
            off = lo | ((hi&0xF0)<<4); ml = (hi&0x0F)+3
            for _ in range(ml):
                b = window[off&0xFFF]; off += 1; out.append(b); window[wp] = b; wp = (wp+1)&0xFFF
        flags >>= 1; fb -= 1
    return bytes(out)

def lzss_compress(src):
    """伪压缩: 全literal。pad到8倍数避免引擎LZSS解压器越界
    (引擎终止条件 pos==comp_size 在8-bit循环外检查,
     不满8字节的末尾block会让pos越过comp_size导致死循环)"""
    src = bytearray(src)
    r = len(src) % 8
    if r != 0:
        src.extend(b'\x00' * (8 - r))
    out = bytearray()
    for i in range(0, len(src), 8):
        out.append(0xFF)
        out.extend(src[i:i+8])
    return bytes(out)

# ── Opcode / 结构体 ──
OPCODES = {
    0x00:'', 0x01:'S', 0x02:'S', 0x03:'HCG', 0x04:'BCG',
    0x05:'CCG', 0x06:'CBCG', 0x07:'CBCG', 0x08:'CFCG',
    0x09:'CBCG', 0x0A:'CBCG', 0x0B:'CI', 0x0C:'I', 0x0D:'CV',
    0x0E:'V', 0x0F:'V', 0x10:'VI', 0x11:'V', 0x12:'V', 0x13:'B',
    0x14:'CI', 0x15:'CG', 0x16:'BCG', 0x17:'I', 0x18:'',
    0x1B:'CG', 0x1C:'CI', 0x1D:'CG', 0x1E:'I', 0x1F:'I',
}
ADDR_OPS = {0x0B:1, 0x0C:0, 0x10:1, 0x14:1, 0x1C:1}
SP = {0x80:'B',0xA0:'B',0xC0:'B',0xE0:'',0xE1:'',0xE2:'',0xE3:'',0xE4:'',0xE5:'',
      0xE6:'',0xE7:'',0xE8:'',0xE9:'',0xEA:'',0xEB:'',0xEC:'',0xED:'',0xEE:'',0xEF:'',
      0xF0:'',0xF1:'h',0xF2:'i',0xF3:'H',0xF4:'',0xF5:'B',0xF6:'B',0xF7:'B',0xF8:'B',0xFF:''}
SPECIAL_SYMS = [(b'\xeb\xa1','*1'),(b'\xeb\xa2','*2'),(b'\xeb\xa3','*3'),(b'\xeb\xa4','*4'),
    (b'\xeb\xa5','*5'),(b'\xeb\xa6','*6'),(b'\xeb\xa7','*7'),(b'\xeb\xa8','*8'),
    (b'\xeb\xa9','*9'),(b'\xeb\xaa','*a'),(b'\xeb\xab','*b'),(b'\xeb\xac','*c'),
    (b'\xeb\xad','*d'),(b'\xeb\xae','*e'),(b'\xeb\xaf','*f')]

def _rC(d,p):
    while p<len(d):
        b=d[p];p+=1
        if b in SP:
            for c in SP[b]:
                if c=='B':p+=1
                elif c in('h','H'):p+=2
                elif c=='i':p+=4
            if b==0xFF:return p
    return p
def _rV(d,p):
    while p<len(d):
        x=d[p];p+=1
        if x==0:return p
        elif x==1:
            while p<len(d) and d[p]!=0:p+=1
            if p<len(d):p+=1
        elif x==2:p=_rC(d,p)
    return p
def _rG(d,p):
    while p<len(d):
        f=d[p];p+=1
        if f==0:return p
        p=_rC(d,p)
    return p

def encode_text(text):
    raw = text.encode('cp932')
    for pat, rep in SPECIAL_SYMS:
        raw = raw.replace(rep.encode('ascii'), pat)
    return raw

# ── 解析MES为切片列表 ──
def parse_mes(data):
    mc = struct.unpack_from('<I', data, 0)[0]
    hs = 4 + mc * 4
    hdr_offsets = [struct.unpack_from('<I', data, 4+i*4)[0] for i in range(mc)]
    slices = []; pos = hs; tid = 0
    while pos < len(data):
        old_rel = pos - hs; op = data[pos]
        if op not in OPCODES:
            slices.append({'r':old_rel, 'b':bytes([op]), 'k':'o'}); pos += 1; continue
        params = OPCODES[op]
        if op in (0x01, 0x02):
            slices.append({'r':old_rel, 'b':bytes([op]), 'k':'t'})
            s = pos+1; e = data.index(b'\x00', s)
            slices.append({'r':s-hs, 'b':data[s:e+1], 'k':'ts', 'i':tid}); tid += 1; pos = e+1
        elif op == 0x17:
            slices.append({'r':old_rel, 'b':bytes([op]), 'k':'mc'})
            slices.append({'r':pos+1-hs, 'b':data[pos+1:pos+5], 'k':'mf'}); pos += 5
        elif op in ADDR_OPS:
            ti = ADDR_OPS[op]; cs = pos; pos += 1; ai = 0; pre = bytearray([op])
            for c in params:
                if c=='I':
                    if ai==ti:
                        if pre: slices.append({'r':old_rel,'b':bytes(pre),'k':'o'}); pre=bytearray()
                        v = struct.unpack_from('<I',data,pos)[0]
                        slices.append({'r':pos-hs,'b':data[pos:pos+4],'k':'af','t':v}); pos+=4; old_rel=pos-hs
                    else: pre+=data[pos:pos+4]; pos+=4
                    ai+=1
                elif c=='S':
                    while data[pos]!=0:pos+=1
                    pos+=1; pre+=data[cs+len(pre):pos] if False else b''; ai+=1
                    # 简化: 把S的字节也加到pre
                elif c=='H': pre+=data[pos:pos+2]; pos+=2; ai+=1
                elif c=='B': pre+=data[pos:pos+1]; pos+=1; ai+=1
                elif c=='C': ns=pos; pos=_rC(data,pos); pre+=data[ns:pos]; ai+=1
                elif c=='V': ns=pos; pos=_rV(data,pos); pre+=data[ns:pos]; ai+=1
                elif c=='G': ns=pos; pos=_rG(data,pos); pre+=data[ns:pos]; ai+=1
                elif c=='F':
                    if data[pos]!=0: break
                    pre+=b'\x00'; pos+=1; ai+=1
            if pre: slices.append({'r':old_rel,'b':bytes(pre),'k':'o'})
        else:
            cs = pos; pos += 1
            for c in params:
                if c=='S':
                    while data[pos]!=0:pos+=1
                    pos+=1
                elif c=='I':pos+=4
                elif c=='H':pos+=2
                elif c=='B':pos+=1
                elif c=='C':pos=_rC(data,pos)
                elif c=='V':pos=_rV(data,pos)
                elif c=='G':pos=_rG(data,pos)
                elif c=='F':
                    if data[pos]!=0:break
                    pos+=1
            slices.append({'r':old_rel,'b':data[cs:pos],'k':'o'})
    return mc, hs, hdr_offsets, slices, tid

# ── 重建 ──
def inject_file(mes_path, json_path, out_path):
    compressed = open(mes_path, 'rb').read()
    data = lzss_decompress(compressed)
    with open(json_path,'r',encoding='utf-8') as f: trans = json.load(f)
    td = {e['id']-1: e.get('message','') for e in trans}
    mc, hs, hdr_off, slices, ttotal = parse_mes(data)

    new = bytearray(); o2n = {}; fixups = []; msg_rels = []
    for s in slices:
        nr = len(new); o2n[s['r']] = nr
        if s['k']=='ts':
            t = td.get(s['i'])
            if t: new += encode_text(t) + b'\x00'
            else: new += s['b']
        elif s['k']=='af':
            fixups.append((len(new), s['t'])); new += b'\x00\x00\x00\x00'
        elif s['k']=='mc':
            msg_rels.append(len(new)); new += s['b']
        elif s['k']=='mf':
            new += s['b']
        else:
            new += s['b']

    for fp, tgt in fixups:
        if tgt in o2n: struct.pack_into('<I', new, fp, o2n[tgt])
        else:
            cs = [k for k in o2n if k <= tgt]
            if cs:
                cl = max(cs); struct.pack_into('<I', new, fp, o2n[cl]+(tgt-cl))

    # header
    hdr = struct.pack('<I', mc)
    for i in range(mc):
        ov = hdr_off[i]
        if ov in o2n: hdr += struct.pack('<I', o2n[ov])
        else:
            cs = [k for k in o2n if k <= ov]
            if cs:
                cl = max(cs); hdr += struct.pack('<I', o2n[cl]+(ov-cl))
            else: hdr += struct.pack('<I', ov)

    result = lzss_compress(hdr + new)
    with open(out_path, 'wb') as f: f.write(result)

    d = len(result) - len(compressed)
    print(f"  {os.path.basename(mes_path)}: {ttotal} texts, {len(compressed)}->{len(result)} ({'+' if d>=0 else ''}{d})")

def main():
    if len(sys.argv) < 3:
        print(f"用法:\n  python {sys.argv[0]} <orig.mes> <trans.json> [output.mes]")
        print(f"  python {sys.argv[0]} <mes_dir> <json_dir> <output_dir>")
        sys.exit(1)
    src, jsrc = sys.argv[1], sys.argv[2]
    if os.path.isdir(src):
        if len(sys.argv)<4: print("批量模式需要output_dir"); sys.exit(1)
        od = sys.argv[3]; os.makedirs(od, exist_ok=True)
        for fn in sorted(os.listdir(src)):
            sp = os.path.join(src,fn); op = os.path.join(od,fn)
            if fn.startswith('_'):
                _tmp = open(sp,'rb').read()
                open(op,'wb').write(_tmp); continue
            if not fn.upper().endswith('.MES'):
                _tmp = open(sp,'rb').read()
                open(op,'wb').write(_tmp); continue
            jp = os.path.join(jsrc, os.path.splitext(fn)[0]+'.json')
            if not os.path.exists(jp):
                _tmp = open(sp,'rb').read()
                open(op,'wb').write(_tmp); continue
            try: inject_file(sp, jp, op)
            except Exception as e: print(f"  ✗ {fn}: {e}")
        print("[INFO] 完成")
    else:
        op = sys.argv[3] if len(sys.argv)>3 else os.path.splitext(src)[0]+'_patched.mes'
        inject_file(src, jsrc, op)

if __name__ == '__main__':
    main()
