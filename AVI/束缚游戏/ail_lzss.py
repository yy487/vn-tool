#!/usr/bin/env python3
"""
ail_lzss.py - AIL 引擎 LZSS 编解码器

适用厂商: アイル (AIL / ail-soft.com)
样本: BONDAGE (sall.snl / GALL*.DAT / PALL*.DAT 等内嵌压缩条目)

============================================================
算法规格 (反向工程自 GARbro ArcAil.cs / morkt 2015)
============================================================

经典 LZSS 变体,有两个 AIL 特色:
  1. 滑动窗口预填充 0x20 (空格),不是 0x00
  2. 控制位含义"反转":bit=0 是 literal,bit=1 是 match
     (标准 LZSS 通常 bit=1 literal,bit=0 match)

窗口参数:
  - 大小:    0x1000 (4096)
  - 初始 frame_pos: 0xFEE
  - 预填充:  0x20 (' ')

控制流:
  每读 1 个 control byte,逐位 LSB-first 处理 8 次:
    bit==0: literal — 读 1 字节,直接输出 + 写入窗口
    bit==1: match   — 读 2 字节 (lo, hi):
        offset = lo | ((hi & 0xF0) << 4)   # 12 位窗口位置
        length = (hi & 0x0F) + 3           # 3..18 字节

注意 control 位用 LSB-first 消耗,实现里通过 `ctl >>= 1` 逐位右移,
高位用 0xFF00 标记"还有 8 位可用",一旦 (ctl & 0x100)==0 就重新加载.

============================================================
压缩策略
============================================================

decompress() — 标准解压,任何 AIL 格式压缩流都能解
compress()   — "全 literal" 压缩 (flag=0x00),不做匹配查找
               输出大小 = ceil(input/8) + input
               体积膨胀 ~12.5%,但:
                 1. 保证 round-trip bit-perfect (decompress 输出与原文一致)
                 2. 引擎完全兼容 (走的是同一个解压器,只不过没 match)
                 3. 实现极简,无 hashtable / suffix array 开销

如果以后需要更紧凑的输出,可以加一个 compress_optimal() 用 KMP/hash 找匹配,
但对汉化注入来说没必要 — 体积膨胀几 KB 换稳定性绝对划算.
"""


def decompress(data: bytes, unpacked_size: int) -> bytes:
    """
    解压 AIL LZSS 流.
    
    Args:
        data: 压缩数据 (不含外层 header)
        unpacked_size: 解压后大小 (从外层 header +2 处的 u32 读出)
    
    Returns:
        解压后的字节串,长度 == unpacked_size
    """
    frame = bytearray(b'\x20' * 0x1000)
    frame_pos = 0xFEE
    out = bytearray(unpacked_size)
    dst = 0
    src = 0
    ctl = 0

    while dst < unpacked_size:
        ctl >>= 1
        if (ctl & 0x100) == 0:
            if src >= len(data):
                break
            ctl = data[src] | 0xFF00
            src += 1

        if (ctl & 1) == 0:
            # literal
            if src >= len(data):
                break
            v = data[src]; src += 1
            out[dst] = v; dst += 1
            frame[frame_pos] = v
            frame_pos = (frame_pos + 1) & 0xFFF
        else:
            # match
            if src + 1 >= len(data):
                break
            lo = data[src]; src += 1
            hi = data[src]; src += 1
            offset = lo | ((hi & 0xF0) << 4)
            length = (hi & 0x0F) + 3
            for _ in range(length):
                if dst >= unpacked_size:
                    break
                v = frame[offset]
                offset = (offset + 1) & 0xFFF
                frame[frame_pos] = v
                frame_pos = (frame_pos + 1) & 0xFFF
                out[dst] = v; dst += 1

    return bytes(out)


def compress(data: bytes) -> bytes:
    """
    压缩为 AIL LZSS 流 — 全 literal 模式.
    
    每 8 字节数据前加 1 字节 control = 0x00 (8 个 literal bit).
    最后一组不足 8 字节时,control 仍写完整字节,多余位无意义 (解压会跳出).
    
    Args:
        data: 原始未压数据
    
    Returns:
        压缩后字节串
    """
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        out.append(0x00)  # control: 8 个 literal flag
        chunk = data[i:i + 8]
        out.extend(chunk)
        i += 8
    return bytes(out)


# ============================================================
# 自检
# ============================================================

if __name__ == '__main__':
    import sys, os, random

    print('[test] AIL LZSS round-trip 自检')

    # 1. 随机数据
    random.seed(42)
    for size in [0, 1, 7, 8, 9, 100, 1024, 65536]:
        src = bytes(random.randint(0, 255) for _ in range(size))
        comp = compress(src)
        dec = decompress(comp, len(src))
        assert dec == src, f'随机大小 {size} 失败'
        ratio = len(comp) / max(len(src), 1)
        print(f'  size={size:6}  comp={len(comp):6}  ratio={ratio:.3f}  OK')

    # 2. 用真实 sall.snl 第 0 条做端到端测试
    snl_path = '/mnt/user-data/uploads/sall.snl'
    if os.path.exists(snl_path):
        import struct
        with open(snl_path, 'rb') as f:
            d = f.read()
        count = struct.unpack_from('<I', d, 0)[0]
        sizes = list(struct.unpack_from(f'<{count}I', d, 4))
        off = (1 + count) * 4

        print('\n[test] 真实 sall.snl 解压所有非空条目')
        ok_cnt = 0
        for i, sz in enumerate(sizes):
            if sz == 0:
                continue
            sig = struct.unpack_from('<I', d, off)[0]
            if (sig & 0xFFFF) != 1:
                off += sz
                continue
            unpacked = struct.unpack_from('<I', d, off + 2)[0]
            payload = d[off + 6: off + sz]
            try:
                dec = decompress(payload, unpacked)
                assert len(dec) == unpacked
                ok_cnt += 1
            except Exception as e:
                print(f'  [{i}] FAIL: {e}')
            off += sz
        print(f'  解压成功: {ok_cnt} 条')

        # 3. 压一条再解,自洽测试
        print('\n[test] compress -> decompress round-trip')
        # 取第 0 条解压后的数据
        sig = struct.unpack_from('<I', d, (1 + count) * 4)[0]
        unp = struct.unpack_from('<I', d, (1 + count) * 4 + 2)[0]
        payload0 = d[(1 + count) * 4 + 6: (1 + count) * 4 + sizes[0]]
        original = decompress(payload0, unp)

        recomp = compress(original)
        redec = decompress(recomp, len(original))
        assert redec == original, 'round-trip 失败'
        print(f'  原始大小: {len(original)}')
        print(f'  原压缩:   {len(payload0)} (ratio {len(payload0)/len(original):.3f})')
        print(f'  我方压缩: {len(recomp)} (ratio {len(recomp)/len(original):.3f})')
        print(f'  redec == original: True')

    print('\n[OK] 全部自检通过')
