#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查某句话在生成字库中是否能查到，并导出该 bank 实际 glyph 预览。
用法:
  python verify_font_line.py build/replace_map.json build/DATA_FONT FONT00 "叮～咚～当～咚～" out.png
"""
import sys, json
from PIL import Image
from font_codec import load_bank, cp932_code
from text_normalize import normalize_text
from hanzi_replacer import ReplaceMapper

if len(sys.argv) < 5:
    print(__doc__); sys.exit(1)
map_path, font_dir, bank_name, text = sys.argv[1:5]
out_png = sys.argv[5] if len(sys.argv) > 5 else f'{bank_name}_line_verify.png'
mapper = ReplaceMapper.load(map_path)
s = normalize_text(text)
source = mapper.apply(s)
bank = load_bank(font_dir, bank_name)
idx = bank.code_to_index()
print('original  :', text)
print('normalized:', s)
print('source    :', source)
print('bank      :', bank_name)
print('\nper char:')
GW, GH = bank.glyph_w, bank.glyph_h
GS = GW * GH
imgs=[]
for t, src in zip(s, source):
    code = cp932_code(src)
    i = idx.get(code)
    print(f'{t} -> {src} -> {src.encode("cp932").hex().upper()} -> index={i}')
    tile = Image.new('RGBA',(GW,GH),(0,0,0,0))
    if i is not None:
        off=i*GS
        for y in range(GH):
            for x in range(GW):
                v=bank.fnt[off+y*GW+x]
                if v:
                    tile.putpixel((x,y),(255,255,255,v))
    imgs.append(tile)
canvas=Image.new('RGBA',(len(imgs)*GW,GH),(30,30,30,255))
for n,tile in enumerate(imgs): canvas.alpha_composite(tile,(n*GW,0))
canvas.save(out_png)
print('\npreview:', out_png)
