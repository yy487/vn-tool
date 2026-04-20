#!/usr/bin/env python3
"""
SNR 脚本文本提取工具 v2.1 — 字节码遍历, 支持 STSL + BTSL
用法: python snr_extract_v2.py BT_SNR.dat [ST_SNR.dat] -o snr_texts.json
"""
import struct, json, os

def get_table(magic):
    op0e = 13 if magic == 'STSL' else 11
    return {
        0x00:(0,0),
        0x07:(15,0), 0x08:(15,0), 0x09:(4,0),
        0x0A:(0,1),  0x0B:(20,0),
        0x0C:(11,1), 0x0D:(10,2), 0x0E:(op0e,0), 0x0F:(1,1),
        0x10:(10,1), 0x11:(20,1), 0x12:(0,1),  0x13:(10,1),
        0x14:(10,0), 0x15:(20,0), 0x16:(20,0), 0x17:(20,1),
        0x18:(16,1), 0x19:(25,0), 0x1A:(15,0), 0x1B:(10,0),
        0x1C:(15,1), 0x1D:(10,0), 0x1E:(10,1), 0x1F:(0,0),
        0x20:(10,1), 0x21:(5,0),  0x22:(30,1), 0x23:(0,0),
        0x24:(10,0), 0x25:(10,0), 0x26:(0,0),  0x27:(0,0),
        0x28:(0,1),  0x29:(5,0),  0x2A:(0,0),  0x2B:(10,0),
        0x2C:(0,0),  0x2D:(10,0), 0x2E:(7,0),  0x2F:(0,0),
        0x30:(5,0),  0x31:(0,0),  0x32:(5,0),  0x33:(25,0),
        0x34:(15,0),
        0x8000:(4,0),
    }

def _rs(d,p):
    if p>=len(d): return 0
    if d[p]==1:
        if p+3>len(d): return 1
        return 1+2+struct.unpack_from('<H',d,p+1)[0]
    return 1

def _cvas(d,p):
    if p>=len(d): return 5
    return 10 if 2<=d[p]<=5 else 5

def parse_snr(data):
    magic = data[0:4].decode('ascii')
    assert magic in ('STSL','BTSL'), f'未知魔数: {magic}'
    off_labels = struct.unpack_from('<I',data,6)[0]
    off_table  = struct.unpack_from('<I',data,10)[0]
    off_data   = struct.unpack_from('<I',data,14)[0]
    pos = off_labels
    for _ in range(2):
        ln = struct.unpack_from('<H',data,pos)[0]
        if ln==0 or ln>256: break
        pos += 2+ln
    count = struct.unpack_from('<I',data,pos)[0]; pos+=4
    labels = []
    for _ in range(count):
        ln = struct.unpack_from('<H',data,pos)[0]
        labels.append(data[pos+2:pos+2+ln].rstrip(b'\0').decode('ascii',errors='replace'))
        pos += 2+ln
    assert pos == off_table
    offsets = [struct.unpack_from('<I',data,off_table+i*4)[0] for i in range(count)]
    assert off_table+count*4 == off_data
    return {'magic':magic,'label_count':count,'labels':labels,
            'offsets':offsets,'off_table':off_table,'off_data':off_data}

def traverse_block(data, bstart, table):
    dsize = struct.unpack_from('<I',data,bstart)[0]
    bend = bstart+4+dsize
    pos = bstart+10
    insns = []
    while pos+1 < bend:
        op_start = pos
        opcode = struct.unpack_from('<H',data,pos)[0]
        pc = op_start-(bstart+4)
        pos += 2
        insn = {'offset':op_start,'pc':pc,'opcode':opcode,'size':0,
                'str_offset':None,'str_len':None,'jt_file_off':None}
        if 0x01<=opcode<=0x06:
            sz = _cvas(data,pos); pos+=sz; insn['size']=2+sz
            insns.append(insn); continue
        if opcode not in table:
            insn['size']=-1; insns.append(insn); break
        fixed,nstr = table[opcode]
        sb = 0
        for si in range(nstr):
            if opcode==0x28 and si==0 and pos+sb<len(data):
                if data[pos+sb]==1 and pos+sb+3<=len(data):
                    slen=struct.unpack_from('<H',data,pos+sb+1)[0]
                    insn['str_offset']=pos+sb+3; insn['str_len']=slen
            sb += _rs(data,pos+sb)
        pos += sb+fixed; insn['size']=2+sb+fixed
        if opcode in (0x07,0x08): insn['jt_file_off']=op_start+2+5+1+5
        elif opcode==0x09: insn['jt_file_off']=op_start+2
        insns.append(insn)
    return insns, bend

def extract_texts(data, info, filename=''):
    table = get_table(info['magic'])
    entries = []
    for bi in range(info['label_count']):
        insns,_ = traverse_block(data, info['offsets'][bi], table)
        for insn in insns:
            if insn['opcode']==0x28 and insn['str_offset'] is not None:
                text = data[insn['str_offset']:insn['str_offset']+insn['str_len']].decode('cp932',errors='replace')
                entries.append({
                    'id':f'{filename}_{len(entries):04d}','name':'','message':text,
                    'block':info['labels'][bi] if bi<len(info['labels']) else f'block_{bi}',
                    'block_index':bi,'file_offset':insn['offset'],'orig_len':insn['str_len'],
                })
    return entries

def verify(data, info):
    table = get_table(info['magic'])
    errors = 0
    for bi in range(info['label_count']):
        bstart = info['offsets'][bi]
        expected = bstart+4+struct.unpack_from('<I',data,bstart)[0]
        insns,_ = traverse_block(data, bstart, table)
        if not insns: continue
        last = insns[-1]
        if last['size']==-1 or last['offset']+last['size']!=expected:
            errors+=1
    total = info['label_count']
    print(f'  验证: {total-errors}/{total} blocks 通过' + (' ✅' if errors==0 else f' ⚠️ ({errors}个异常)'))
    return errors==0

def main():
    import argparse
    p = argparse.ArgumentParser(description='SNR文本提取 v2.1')
    p.add_argument('files',nargs='+')
    p.add_argument('-o','--output',default='snr_texts.json')
    args = p.parse_args()
    all_e = []
    for fpath in args.files:
        fname = os.path.splitext(os.path.basename(fpath))[0]
        data = open(fpath,'rb').read()
        info = parse_snr(data)
        verify(data, info)
        entries = extract_texts(data, info, fname)
        all_e.extend(entries)
        print(f'{fpath}: {info["magic"]}, {info["label_count"]} blocks, {len(entries)} texts')
    out = [{'id':e['id'],'name':e['name'],'message':e['message']} for e in all_e]
    with open(args.output,'w',encoding='utf-8') as f:
        json.dump(out,f,ensure_ascii=False,indent=2)
    print(f'导出 {len(out)} 条 → {args.output}')

if __name__=='__main__': main()
