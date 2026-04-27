# -*- coding: utf-8 -*-
"""
UMakeMe! / ARCHIVE DAT 解包工具
用法:
    python umake_extract.py <input.dat> <output_dir>

会在 output_dir 下生成:
    <output_dir>/<filename>          每个条目解密后的原始数据
    <output_dir>/_meta.json          重建所需的元数据 (顺序/tag8/tail/保留字段)
"""
import sys, os, json, struct
import umake_codec as codec


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    in_path, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    raw = open(in_path, 'rb').read()
    filekey = codec.derive_filekey(raw)
    info = codec.parse_header(raw, filekey)
    entries, _ = codec.parse_index(raw, filekey, info)

    print(f"[+] file size     : {len(raw)} (0x{len(raw):x})")
    print(f"[+] filekey       : {filekey.hex()}")
    print(f"[+] index_off_abs : 0x{info['index_off_abs']:x}")
    print(f"[+] entry_count   : {info['entry_count']}")

    meta = {
        'pre17'       : raw[0x00:0x11].hex(),
        'pad5'        : raw[0x19:0x1E].hex(),
        'filekey'     : filekey.hex(),
        'header_plain': info['header_dec'].hex(),
        'entries'     : [],
    }

    for e in entries:
        name = e['name'].decode('cp932', errors='replace')
        data = codec.read_file_data(raw, filekey, e)
        out_path = os.path.join(out_dir, name)
        if os.path.sep in name or '..' in name:
            raise RuntimeError(f"suspicious name: {name!r}")
        with open(out_path, 'wb') as f:
            f.write(data)
        meta['entries'].append({
            'name' : e['name'].hex(),     # 原始字节保真
            'size' : e['size'],
            'raw'  : e['raw'].hex(),      # 完整 276B 明文, repack 用
        })

    with open(os.path.join(out_dir, '_meta.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"[+] extracted {len(entries)} files -> {out_dir}")


if __name__ == '__main__':
    main()
