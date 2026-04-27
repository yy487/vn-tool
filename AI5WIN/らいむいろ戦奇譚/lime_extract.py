#!/usr/bin/env python3
"""
AI5WIN v2 MES 文本提取工具
输入: LZSS压缩的MES文件 (直接从ARC解包的原始数据)
输出: GalTransl兼容JSON

用法:
  python lime_extract.py <input.mes> [output.json]
  python lime_extract.py <mes_dir>   <json_dir>     (批量)
"""
import struct, json, sys, os

# ── LZSS解压 ──
def lzss_decompress(src):
    window = bytearray(0x1000); wp = 0xFEE; out = bytearray()
    sp = 0; end = len(src); flags = 0; fb = 0
    while sp < end:
        if fb == 0:
            flags = src[sp]; sp += 1; fb = 8
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

# ── Opcode定义 ──
OPCODES = {
    0x00:'', 0x01:'S', 0x02:'S', 0x03:'HCG', 0x04:'BCG',
    0x05:'CCG', 0x06:'CBCG', 0x07:'CBCG', 0x08:'CFCG',
    0x09:'CBCG', 0x0A:'CBCG', 0x0B:'CI', 0x0C:'I', 0x0D:'CV',
    0x0E:'V', 0x0F:'V', 0x10:'VI', 0x11:'V', 0x12:'V', 0x13:'B',
    0x14:'CI', 0x15:'CG', 0x16:'BCG', 0x17:'I', 0x18:'',
    0x1B:'CG', 0x1C:'CI', 0x1D:'CG', 0x1E:'I', 0x1F:'I',
}
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

def decode_text(raw):
    for pat, rep in SPECIAL_SYMS:
        raw = raw.replace(pat, rep.encode('ascii'))
    try: return raw.decode('cp932')
    except: return raw.hex(' ')

def extract_file(mes_path, json_path):
    compressed = open(mes_path, 'rb').read()
    data = lzss_decompress(compressed)
    mc = struct.unpack_from('<I', data, 0)[0]
    hs = 4 + mc * 4
    entries = []; pos = hs; tid = 0
    while pos < len(data):
        op = data[pos]; pos += 1
        if op not in OPCODES: continue
        params = OPCODES[op]
        if op in (0x01, 0x02):
            s = pos; e = data.index(b'\x00', pos)
            tid += 1
            entries.append({"id": tid, "name": "", "message": decode_text(data[s:e])})
            pos = e + 1
        else:
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
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"  {os.path.basename(mes_path)}: {len(compressed)}->{len(data)} bytes, {len(entries)} texts")
    return len(entries)

def main():
    if len(sys.argv) < 2:
        print(f"用法:\n  python {sys.argv[0]} <input.mes> [output.json]")
        print(f"  python {sys.argv[0]} <mes_dir>   <json_dir>")
        sys.exit(1)
    src = sys.argv[1]
    if os.path.isdir(src):
        out = sys.argv[2] if len(sys.argv)>2 else src+'_json'
        os.makedirs(out, exist_ok=True)
        files = sorted(set(f for f in os.listdir(src) if f.upper().endswith('.MES')))
        total = sum(extract_file(os.path.join(src,f), os.path.join(out, os.path.splitext(f)[0]+'.json')) for f in files)
        print(f"[INFO] {len(files)} 文件, {total} 条文本")
    else:
        jp = sys.argv[2] if len(sys.argv)>2 else os.path.splitext(src)[0]+'.json'
        extract_file(src, jp)

if __name__ == '__main__':
    main()
