"""
AI6WIN / AI5WIN ARC archive-level codec.

Only the archive index codec lives here: the filename cipher and the fixed
index-entry field layout. Payload-level LZSS is a separate concern (used by
text-extraction tools, not by the archive packer/extractor).

Index entry layout (0x110 bytes):
  0x00   0x104  filename             (CP932, NUL-terminated, subtraction-cipher)
  0x104  4      compressed_size      (u32 BIG-endian)
  0x108  4      uncompressed_size    (u32 BIG-endian)
  0x10C  4      offset               (u32 BIG-endian, absolute file offset)

Filename cipher (applied per entry, in place):
  decrypt: plain[j] = cipher[j] - key  (key = name_length + 1, decremented per byte)
  encrypt: cipher[j] = plain[j] + key  (same key schedule)

Archive header:
  offset  size  field
  0x00    4     count                 (u32 LITTLE-endian)
  0x04    ...   index[count]          each entry = 0x110 bytes
  ...     ...   payloads in order

Verified against AI6WIN3.exe (index-read loop at ~0x40FC00) and GameRes Ai6Opener.
"""

from __future__ import annotations

import struct

ENTRY_NAME_SIZE = 0x104
ENTRY_META_SIZE = 12          # 3 x u32 BE
ENTRY_TOTAL_SIZE = 0x110      # 0x104 + 12
HEADER_SIZE = 4               # file count u32 LE
MAX_ENTRIES = 0x20000         # sanity bound; matches GARbro's IsSaneCount spirit


def decrypt_filename(raw: bytes) -> str:
    """Decrypt a 0x104-byte filename field.

    `raw` is exactly the cipher bytes; NUL terminator determines name length.
    Returns the CP932-decoded filename.
    """
    nul = raw.find(b"\x00")
    n = nul if nul != -1 else len(raw)
    if n == 0:
        raise ValueError("empty filename slot")
    dec = bytearray(raw[:n])
    key = (n + 1) & 0xFF
    for j in range(n):
        dec[j] = (dec[j] - key) & 0xFF
        key = (key - 1) & 0xFF
    return dec.decode("cp932")


def encrypt_filename(name: str) -> bytes:
    """Encrypt a filename back into a 0x104-byte field (NUL-padded)."""
    plain = name.encode("cp932")
    n = len(plain)
    if n == 0:
        raise ValueError("empty filename not allowed")
    if n > ENTRY_NAME_SIZE - 1:
        raise ValueError(f"filename too long: {n} > {ENTRY_NAME_SIZE - 1}")
    enc = bytearray(plain)
    key = (n + 1) & 0xFF
    for j in range(n):
        enc[j] = (enc[j] + key) & 0xFF
        key = (key - 1) & 0xFF
    return bytes(enc).ljust(ENTRY_NAME_SIZE, b"\x00")


def pack_entry_meta(compressed_size: int, uncompressed_size: int, offset: int) -> bytes:
    """Pack the 12-byte metadata (3 x u32 BE) that follows the filename."""
    return struct.pack(">III", compressed_size, uncompressed_size, offset)


def unpack_entry_meta(buf: bytes) -> tuple[int, int, int]:
    """Inverse of pack_entry_meta; returns (compressed, uncompressed, offset)."""
    return struct.unpack(">III", buf)


def pack_header(count: int) -> bytes:
    """Pack the 4-byte file count prefix (u32 LE)."""
    return struct.pack("<I", count)


def unpack_header(buf: bytes) -> int:
    """Inverse of pack_header."""
    return struct.unpack("<I", buf[:4])[0]
