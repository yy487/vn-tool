#!/usr/bin/env python3
"""
SNR 脚本文本注入工具 v2.1 — 字节码遍历 + 跳转修正, 支持 STSL + BTSL

用法:
  提取: python snr_inject_v2.py BT_SNR.dat --extract-only -i out.json
  注入: python snr_inject_v2.py BT_SNR.dat ST_SNR.dat -i translated.json -o output/
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
    off_labels=struct.unpack_from('<I',data,6)[0]
    off_table=struct.unpack_from('<I',data,10)[0]
    off_data=struct.unpack_from('<I',data,14)[0]
    pos=off_labels
    for _ in range(2):
        ln=struct.unpack_from('<H',data,pos)[0]
        if ln==0 or ln>256: break
        pos+=2+ln
    count=struct.unpack_from('<I',data,pos)[0]; pos+=4
    labels=[]
    for _ in range(count):
        ln=struct.unpack_from('<H',data,pos)[0]
        labels.append(data[pos+2:pos+2+ln].rstrip(b'\0').decode('ascii',errors='replace'))
        pos+=2+ln
    assert pos==off_table
    offsets=[struct.unpack_from('<I',data,off_table+i*4)[0] for i in range(count)]
    assert off_table+count*4==off_data
    return {'magic':magic,'label_count':count,'labels':labels,
            'offsets':offsets,'off_table':off_table,'off_data':off_data}

def traverse_block(data, bstart, table):
    dsize=struct.unpack_from('<I',data,bstart)[0]
    bend=bstart+4+dsize; pos=bstart+10; insns=[]
    while pos+1<bend:
        op_start=pos; opcode=struct.unpack_from('<H',data,pos)[0]
        pc=op_start-(bstart+4); pos+=2
        insn={'offset':op_start,'pc':pc,'opcode':opcode,'size':0,
              'str_offset':None,'str_len':None,'jt_file_off':None}
        if 0x01<=opcode<=0x06:
            sz=_cvas(data,pos); pos+=sz; insn['size']=2+sz
            insns.append(insn); continue
        if opcode not in table:
            insn['size']=-1; insns.append(insn); break
        fixed,nstr=table[opcode]; sb=0
        for si in range(nstr):
            if opcode==0x28 and si==0 and pos+sb<len(data):
                if data[pos+sb]==1 and pos+sb+3<=len(data):
                    slen=struct.unpack_from('<H',data,pos+sb+1)[0]
                    insn['str_offset']=pos+sb+3; insn['str_len']=slen
            sb+=_rs(data,pos+sb)
        pos+=sb+fixed; insn['size']=2+sb+fixed
        if opcode in(0x07,0x08): insn['jt_file_off']=op_start+2+5+1+5
        elif opcode==0x09: insn['jt_file_off']=op_start+2
        insns.append(insn)
    return insns,bend

def extract_texts(data, info, filename=''):
    table=get_table(info['magic']); entries=[]
    for bi in range(info['label_count']):
        insns,_=traverse_block(data,info['offsets'][bi],table)
        for insn in insns:
            if insn['opcode']==0x28 and insn['str_offset'] is not None:
                text=data[insn['str_offset']:insn['str_offset']+insn['str_len']].decode('cp932',errors='replace')
                entries.append({'id':f'{filename}_{len(entries):04d}','name':'','message':text,
                    'block':info['labels'][bi] if bi<len(info['labels']) else f'block_{bi}',
                    'block_index':bi,'file_offset':insn['offset'],'orig_len':insn['str_len']})
    return entries

def inject_block(block_data, insns, text_map):
    if not text_map: return block_data
    bd=bytearray(block_data); BASE=4
    repls=[]
    for idx,new_bytes in sorted(text_map.items()):
        insn=insns[idx]; bd_off=insn['pc']+BASE
        new_insn=bytearray(b'\x28\x00\x01')
        new_insn.extend(struct.pack('<H',len(new_bytes)))
        new_insn.extend(new_bytes)
        repls.append((bd_off,insn['size'],bytes(new_insn),insn['pc']))
    repls.sort(key=lambda x:x[0])
    jumps=[]
    for insn in insns:
        if insn['jt_file_off'] is not None:
            jt_bd=insn['pc']+BASE+(insn['jt_file_off']-insn['offset'])
            jumps.append((jt_bd,struct.unpack_from('<I',bd,jt_bd)[0]))
    result=bytearray(); src=0; deltas=[]
    for bd_off,old_sz,new_insn,pc in repls:
        result.extend(bd[src:bd_off]); result.extend(new_insn)
        deltas.append((pc,len(new_insn)-old_sz)); src=bd_off+old_sz
    result.extend(bd[src:])
    for jt_bd,orig_target in jumps:
        new_target=orig_target
        for rpc,delta in deltas:
            if orig_target>rpc: new_target+=delta
        new_jt=jt_bd
        for bd_off,old_sz,new_insn,_ in repls:
            if jt_bd>bd_off: new_jt+=len(new_insn)-old_sz
        struct.pack_into('<I',result,new_jt,new_target)
    struct.pack_into('<I',result,0,len(result)-4)
    return bytes(result)

def inject_texts(data, info, entries):
    table=get_table(info['magic'])
    offsets=info['offsets']; off_data=info['off_data']; count=info['label_count']
    by_block={}
    for e in entries:
        bi=e['block_index']
        if bi not in by_block: by_block[bi]=[]
        by_block[bi].append(e)
    header=bytearray(data[:off_data]); new_blocks=bytearray()
    new_offsets=[]; total_changed=0
    for bi in range(count):
        bstart=offsets[bi]; bend=offsets[bi+1] if bi+1<count else len(data)
        block_data=data[bstart:bend]
        new_offsets.append(off_data+len(new_blocks))
        if bi not in by_block:
            new_blocks.extend(block_data); continue
        insns,_=traverse_block(data,bstart,table)
        text_map={}
        for e in by_block[bi]:
            for ii,insn in enumerate(insns):
                if insn['offset']==e['file_offset'] and insn['opcode']==0x28:
                    try: nb=e['message'].encode('cp932')
                    except UnicodeEncodeError:
                        print(f'  警告: cp932编码失败 {e["id"]}'); break
                    text_map[ii]=nb; total_changed+=1; break
        if text_map: block_data=inject_block(block_data,insns,text_map)
        new_blocks.extend(block_data)
    off_table=info['off_table']
    for bi,no in enumerate(new_offsets):
        struct.pack_into('<I',header,off_table+bi*4,no)
    struct.pack_into('<I',header,14,new_offsets[0])
    return bytes(header)+bytes(new_blocks),total_changed

def verify(new_data):
    info=parse_snr(new_data); table=get_table(info['magic']); errors=0
    for bi in range(info['label_count']):
        bstart=info['offsets'][bi]; expected=bstart+4+struct.unpack_from('<I',new_data,bstart)[0]
        insns,_=traverse_block(new_data,bstart,table)
        if not insns: continue
        last=insns[-1]
        if last['size']==-1 or last['offset']+last['size']!=expected: errors+=1
    total=info['label_count']
    print(f'  验证: {total-errors}/{total} blocks 通过'+(' ✅' if errors==0 else f' ⚠️ ({errors}个异常)'))
    return errors==0

def main():
    import argparse
    p=argparse.ArgumentParser(description='SNR注入 v2.1 (STSL+BTSL)')
    p.add_argument('files',nargs='+')
    p.add_argument('-i','--input',required=True)
    p.add_argument('-o','--outdir',default='output')
    p.add_argument('--extract-only',action='store_true')
    args=p.parse_args()
    if args.extract_only:
        all_e=[]
        for fpath in args.files:
            fname=os.path.splitext(os.path.basename(fpath))[0]
            data=open(fpath,'rb').read(); info=parse_snr(data)
            entries=extract_texts(data,info,fname); all_e.extend(entries)
            print(f'{fpath}: {info["magic"]}, {info["label_count"]} blocks, {len(entries)} texts')
        out=[{'id':e['id'],'name':e['name'],'message':e['message']} for e in all_e]
        with open(args.input,'w',encoding='utf-8') as f:
            json.dump(out,f,ensure_ascii=False,indent=2)
        print(f'导出 {len(out)} 条 → {args.input}'); return
    with open(args.input,'r',encoding='utf-8') as f: translated=json.load(f)
    trans_by_file={}
    for t in translated:
        fid=t['id'].rsplit('_',1)[0]
        if fid not in trans_by_file: trans_by_file[fid]=[]
        trans_by_file[fid].append(t)
    os.makedirs(args.outdir,exist_ok=True)
    for fpath in args.files:
        fname=os.path.splitext(os.path.basename(fpath))[0]
        data=open(fpath,'rb').read(); info=parse_snr(data)
        orig_entries=extract_texts(data,info,fname)
        print(f'{fpath}: {info["magic"]}, {info["label_count"]} blocks, {len(orig_entries)} texts')
        trans_list=trans_by_file.get(fname,[])
        trans_map={t['id']:t['message'] for t in trans_list}
        for e in orig_entries:
            if e['id'] in trans_map: e['message']=trans_map[e['id']]
        new_data,changed=inject_texts(data,info,orig_entries)
        outpath=os.path.join(args.outdir,os.path.basename(fpath))
        with open(outpath,'wb') as f: f.write(new_data)
        print(f'  {len(data)} → {len(new_data)} bytes, 变更: {changed}')
        verify(new_data)

if __name__=='__main__': main()
