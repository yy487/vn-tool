# -*- coding: utf-8 -*-
"""
UMakeMe! / ARCHIVE DAT 封包工具
用法:
    python umake_pack.py <input_dir> <output.dat>

input_dir 必须是 umake_extract.py 的输出目录, 包含:
    _meta.json
    每个条目的原始数据文件
"""
import sys, os, json, struct
import umake_codec as codec


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    in_dir, out_path = sys.argv[1], sys.argv[2]

    with open(os.path.join(in_dir, '_meta.json'), 'r', encoding='utf-8') as f:
        meta = json.load(f)

    filekey      = bytes.fromhex(meta['filekey'])
    pre17        = bytes.fromhex(meta['pre17'])
    pad5         = bytes.fromhex(meta['pad5'])
    header_plain = bytes.fromhex(meta['header_plain'])

    entries_in = []
    for em in meta['entries']:
        name_b = bytes.fromhex(em['name'])
        name_s = name_b.decode('cp932', errors='replace')
        data = open(os.path.join(in_dir, name_s), 'rb').read()
        if len(data) != em['size']:
            print(f"[!] {name_s} size changed: {em['size']} -> {len(data)}")
        entries_in.append((
            bytes.fromhex(em['raw']),    # 276B 明文条目
            data,
        ))

    blob = codec.build_file(
        entries_in,
        filekey=filekey,
        header_plain=header_plain,
        pre17=pre17,
        pad5=pad5,
    )
    with open(out_path, 'wb') as f:
        f.write(blob)

    print(f"[+] packed {len(entries_in)} files -> {out_path} ({len(blob)} bytes)")


if __name__ == '__main__':
    main()
