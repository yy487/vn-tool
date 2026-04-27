"""
Silky / AI-series LZSS decompressor.

Used by text-extraction tools to read MES payloads out of the directory
produced by arc_extract.py. The archive packer does NOT import this module —
it writes payload bytes verbatim.

Stream format (verified against AI6WIN3.exe FUN_004132A0):
  - Ring buffer: 4096 bytes, initial fill = 0x00, initial write pos = 0xFEE.
  - Control flag byte, LSB first, refilled every 8 tokens.
      bit = 1  -> literal: copy 1 byte to output and ring
      bit = 0  -> 2-byte back-reference [b0, b1]:
          offset = ((b1 & 0xF0) << 4) | b0     # ring index, 12-bit
          length = (b1 & 0x0F) + 3              # 3..18
          for i in range(length):
              byte = ring[(offset + i) & 0xFFF]
              out.append(byte); ring[ring_pos] = byte
              ring_pos = (ring_pos + 1) & 0xFFF
"""

from __future__ import annotations

RING_SIZE = 0x1000
RING_MASK = RING_SIZE - 1
RING_INIT_POS = 0xFEE
MATCH_MIN = 3


def decompress(src: bytes, unpacked_size: int) -> bytes:
    """Decompress an AI-series LZSS stream.

    Args:
        src: compressed bytes (the exact archive slice for the entry).
        unpacked_size: expected output size, from the index's uncompressed_size.

    Returns:
        Decompressed bytes of length unpacked_size.
    """
    ring = bytearray(RING_SIZE)
    out = bytearray()
    src_pos = 0
    ring_pos = RING_INIT_POS
    flags = 0

    while len(out) < unpacked_size:
        flags >>= 1
        if (flags & 0x100) == 0:
            if src_pos >= len(src):
                break
            flags = src[src_pos] | 0xFF00
            src_pos += 1

        if src_pos >= len(src):
            break

        if flags & 1:
            b = src[src_pos]
            src_pos += 1
            out.append(b)
            ring[ring_pos] = b
            ring_pos = (ring_pos + 1) & RING_MASK
        else:
            if src_pos + 1 >= len(src):
                break
            b0 = src[src_pos]
            b1 = src[src_pos + 1]
            src_pos += 2
            off = ((b1 & 0xF0) << 4) | b0
            ln = (b1 & 0x0F) + MATCH_MIN
            for _ in range(ln):
                b = ring[off & RING_MASK]
                out.append(b)
                ring[ring_pos] = b
                ring_pos = (ring_pos + 1) & RING_MASK
                off += 1
                if len(out) >= unpacked_size:
                    break

    if len(out) != unpacked_size:
        raise ValueError(
            f"LZSS decompress size mismatch: got {len(out)}, expected {unpacked_size}"
        )
    return bytes(out)
