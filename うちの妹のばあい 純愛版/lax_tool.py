# -*- coding: utf-8 -*-
"""
lax_tool.py  --  Lapis LAX archive unpacker / repacker

File format (confirmed against uchiimoj.exe):

  [+0x00]  8B   "$LapH__\\0"                    file signature
  [+0x08]  ...  data area (each file = concatenated _AF blocks)
  [idx ]   ...  single _AF1 block; decompressed = entry_count * 0x128
  [-0x28]  8B   "$LapI__\\0"
  [-0x20]  4B   entry_count
  [-0x1c]  4B   index_offset
  [-0x18]  4B   index_unpacked_size  ( = entry_count * 0x128 )
  [-0x14]  4B   index_packed_size
  [-0x10]  4B   tail_checksum?    (0x4926f9 on our sample; reproduced as-is)
  [-0x0c]  4B   data_area_size    ( = index_offset - 8 )
  [-0x08]  4B   constant 0xdc     (Lapis build/version marker)
  [-0x04]  4B   zero

Index entry (0x128 bytes):

  +0x00  8B   "$LapF__\\0"
  +0x08  8B   FILETIME
  +0x10  4B   unpacked_size   (final decompressed size)
  +0x14  4B   packed_size     (bytes in archive)
  +0x18  4B   offset          (relative to +8, cumulative)
  +0x1c  4B   flags|crc       (hi16 seems to be category flag, lo16 varies per-file)
  +0x20  4B   file_id         (monotonically increasing; engine-global asset id)
  +0x24  0x104B  filename     (cp932, NUL-terminated)

We operate at the _AF-block layer but DO NOT decompress file payloads during
unpack -- we dump bytes verbatim.  Repack is therefore bit-perfect provided
nobody edits the payloads.
"""
import argparse
import json
import os
import struct
import sys
from pathlib import Path

# ---- LZSS (_AF1) ----
# Parameters verified from FUN_00466ff0 in uchiimoj.exe:
#   ring buffer N=0x1000, init to zero, write ptr starts at 0xFEE
#   flag bit=1 -> literal, bit=0 -> match
#   match: 2 bytes, offset = lo | ((hi & 0xF0) << 4), length = (hi & 0x0F) + 3

def lzss_decompress_af1(payload: bytes, out_size: int) -> bytes:
    N = 0x1000
    ring = bytearray(N)
    r = 0xFEE
    out = bytearray()
    p = 0
    flags = 0
    bits_left = 0
    n = len(payload)
    while len(out) < out_size:
        if bits_left == 0:
            if p >= n:
                break
            flags = payload[p]
            p += 1
            bits_left = 8
        bit = flags & 1
        flags >>= 1
        bits_left -= 1
        if bit:
            if p >= n:
                break
            b = payload[p]
            p += 1
            out.append(b)
            ring[r] = b
            r = (r + 1) & 0xFFF
        else:
            if p + 1 >= n:
                break
            lo = payload[p]
            hi = payload[p + 1]
            p += 2
            off = lo | ((hi & 0xF0) << 4)
            ln = (hi & 0x0F) + 3
            for k in range(ln):
                if len(out) >= out_size:
                    break
                b = ring[(off + k) & 0xFFF]
                out.append(b)
                ring[r] = b
                r = (r + 1) & 0xFFF
    return bytes(out)


def lzss_compress_af1(data: bytes) -> bytes:
    """
    Produce a decoder-compatible _AF1 payload (no 10-byte block header).

    We track the *decoder's view*: for every byte written so far we know its
    absolute position (matching i) and its ring address (matching r when we
    wrote it).  A back-reference at `best_off` must reproduce exactly what
    the decoder gets when it reads `ring[(best_off + k) & 0xFFF]` in order
    -- including the RLE case where reads cross r into positions we're
    writing in the same match.

    Strategy: for each position, use a hash chain indexed by the previous
    absolute positions where this 3-gram appeared.  To validate a candidate
    `cand_pos` (absolute), simulate the decoder: the bytes it would emit are
        data[cand_pos + k]  for k < (cur_pos - cand_pos)
    and then, for k >= (cur_pos - cand_pos), the byte the decoder just
    emitted at position  cur_pos + (k - (cur_pos - cand_pos)).
    This lets the encoder honor RLE-style overlapping matches correctly.
    """
    MIN_MATCH = 3
    MAX_MATCH = 18
    N = 0x1000

    n = len(data)
    # hash chain over absolute positions in `data`
    head = [-1] * 0x1000
    prev = [-1] * n

    def h3(b0, b1, b2):
        return ((b0 << 8) ^ (b1 << 4) ^ b2) & 0xFFF

    # The encoder also mirrors the ring write pointer `r` for address math.
    r = 0xFEE
    # Map absolute pos -> ring address where that byte lives in the decoder
    # (only for positions within the last N bytes -- older positions have
    # been overwritten and aren't referenceable).
    # ring_addr_of[pos] = (0xFEE + pos) & 0xFFF ; this is by construction
    # since the ring advances by 1 per output byte.

    def ring_addr(pos):
        return (0xFEE + pos) & 0xFFF

    out = bytearray()
    ctrl_pos = -1
    ctrl_val = 0
    ctrl_bit = 8

    def flush_ctrl():
        if ctrl_pos >= 0:
            out[ctrl_pos] = ctrl_val & 0xFF

    i = 0
    while i < n:
        if ctrl_bit == 8:
            flush_ctrl()
            ctrl_pos = len(out)
            out.append(0)
            ctrl_val = 0
            ctrl_bit = 0

        best_len = 0
        best_off = 0
        if i + MIN_MATCH <= n:
            # only look back within the ring window
            window_start = max(0, i - (N - MAX_MATCH))
            cand_pos = head[h3(data[i], data[i+1], data[i+2])]
            tries = 0
            while cand_pos != -1 and cand_pos >= window_start and tries < 256:
                tries += 1
                # simulate decoder reading `ring[(ring_addr(cand_pos) + k) & 0xFFF]`
                # and check it matches data[i + k]
                # For k where cand_pos + k < i: decoder reads data[cand_pos + k] (still in ring).
                # For k where cand_pos + k >= i: decoder reads what we just wrote at
                #   position i + (k - (i - cand_pos)) == cand_pos + k.
                # In both cases it resolves to data[cand_pos + k] as long as that
                # position exists and we haven't advanced past the match length.
                # => match byte is always data[cand_pos + k], BUT it must equal
                #    data[i + k].  For k in [0, i - cand_pos) it's straight history;
                #    for k >= i - cand_pos it's self-reference into bytes we are
                #    currently emitting (RLE).
                delta = i - cand_pos
                k = 0
                while (k < MAX_MATCH
                       and i + k < n):
                    # virtual decoder byte at this k:
                    src_pos = cand_pos + k
                    if src_pos < i:
                        src_byte = data[src_pos]
                    else:
                        # self-reference: decoder reads what encoder just emitted
                        # which *must* equal data[i + (src_pos - i)] for the encoder
                        # to be legal -- that's data[src_pos] still (we're just
                        # checking data[i+k] against data[src_pos] where src_pos = i+k-delta)
                        # Equivalent: data[i + k - delta]
                        src_byte = data[i + k - delta]
                    if src_byte != data[i + k]:
                        break
                    k += 1
                if k >= MIN_MATCH and k > best_len:
                    best_len = k
                    best_off = ring_addr(cand_pos)
                    if k == MAX_MATCH:
                        break
                cand_pos = prev[cand_pos]

        if best_len >= MIN_MATCH:
            lo = best_off & 0xFF
            hi = ((best_off >> 4) & 0xF0) | ((best_len - 3) & 0x0F)
            out.append(lo)
            out.append(hi)
            # advance i and update hash chain
            for _ in range(best_len):
                if i + 2 < n:
                    h = h3(data[i], data[i+1], data[i+2])
                    prev[i] = head[h]
                    head[h] = i
                i += 1
                r = (r + 1) & 0xFFF
            # ctrl bit = 0 (default)
        else:
            ctrl_val |= (1 << ctrl_bit)
            out.append(data[i])
            if i + 2 < n:
                h = h3(data[i], data[i+1], data[i+2])
                prev[i] = head[h]
                head[h] = i
            i += 1
            r = (r + 1) & 0xFFF
        ctrl_bit += 1

    flush_ctrl()
    return bytes(out)


def build_af1_block(data: bytes) -> bytes:
    """Wrap data in an _AF1 single-stage block header (10B) + LZSS payload."""
    payload = lzss_compress_af1(data)
    total = 10 + len(payload)
    if total > 0xFFFF:
        raise ValueError(
            f"compressed block too large ({total} bytes); use "
            "compress_af_chain() which splits into multiple _AF1 blocks."
        )
    hdr = bytearray(10)
    hdr[0:3] = b"_AF"
    hdr[3:4] = b"1"
    hdr[4:6] = total.to_bytes(2, "little")
    hdr[6:8] = (0).to_bytes(2, "little")
    hdr[8:10] = (len(data) & 0xFFFF).to_bytes(2, "little")
    return bytes(hdr) + payload


# -------- _AF chain: a file stored as N concatenated _AF blocks --------
#
# Observed in scenario.lax: each .te file is 1..N _AF1 blocks back-to-back,
# each block's output_size <= 0x8000 (32 KB) -- the engine's chunk granularity.
# `FUN_00458fc0` in uchiimoj.exe iterates blocks via block-hdr[4..6] stride.

CHUNK_SIZE = 0x8000  # engine's natural output-chunk granularity


def decompress_af_chain(data: bytes) -> tuple:
    """
    Walk a concatenation of _AF blocks, decompressing each in turn.
    Returns (decompressed_bytes, per_block_info).
    per_block_info = [(alg_byte, output_size, total_size), ...]
    """
    out = bytearray()
    blocks = []
    off = 0
    n = len(data)
    while off < n:
        if off + 10 > n or data[off:off+3] != b"_AF":
            raise ValueError(
                f"_AF chain: bad block magic @0x{off:x}: "
                f"{data[off:off+4]!r}")
        alg   = data[off+3:off+4]
        total = int.from_bytes(data[off+4:off+6], "little")
        pre   = int.from_bytes(data[off+6:off+8], "little")
        outsz = int.from_bytes(data[off+8:off+10], "little")
        if total < 10 or off + total > n:
            raise ValueError(
                f"_AF block @0x{off:x}: bad total=0x{total:x}")
        payload = data[off+10:off+total]
        if pre != 0:
            raise NotImplementedError(
                f"_AF block @0x{off:x}: two-stage (pre=0x{pre:x}) "
                "not implemented for file payloads")
        if alg == b"1":
            chunk = lzss_decompress_af1(payload, outsz)
        elif alg == b"2":
            raise NotImplementedError(
                f"_AF2 (Huffman) @0x{off:x} not implemented")
        else:
            # "other" -> memcpy per FUN_00444d80
            chunk = payload[:outsz]
        if len(chunk) != outsz:
            raise ValueError(
                f"_AF block @0x{off:x}: decoded {len(chunk)} != "
                f"declared {outsz}")
        out.extend(chunk)
        blocks.append(dict(alg=alg.decode("ascii"),
                           output_size=outsz,
                           total_size=total))
        off += total
    return bytes(out), blocks


def compress_af_chain(data: bytes, block_sizes: list = None) -> bytes:
    """
    Split `data` into chunks and emit each as an _AF1 block.
    If `block_sizes` is given (from the original file), we honor it so the
    output is structurally closer to the original.  Otherwise we chunk by
    CHUNK_SIZE.
    """
    if not data:
        return b""
    if block_sizes:
        if sum(block_sizes) != len(data):
            # manifest block sizes don't match actual data (user edited) --
            # fall back to uniform chunking
            block_sizes = None
    if not block_sizes:
        block_sizes = []
        remaining = len(data)
        while remaining > 0:
            take = min(CHUNK_SIZE, remaining)
            block_sizes.append(take)
            remaining -= take

    out = bytearray()
    p = 0
    for sz in block_sizes:
        block = build_af1_block(data[p:p+sz])
        # build_af1_block enforces total <= 0xFFFF; CHUNK_SIZE output tops at
        # ~32K raw which compresses comfortably under 64K.
        out.extend(block)
        p += sz
    return bytes(out)


# -------- archive layer --------

SIG_FILE    = b"$LapH__\x00"
SIG_ENTRY   = b"$LapF__\x00"
SIG_TAIL    = b"$LapI__\x00"
ENTRY_SIZE  = 0x128
TAIL_SIZE   = 0x28
DATA_BASE   = 8


def parse_entry(buf: bytes) -> dict:
    assert buf[:8] == SIG_ENTRY, f"bad entry magic: {buf[:8]!r}"
    ft   = int.from_bytes(buf[0x08:0x10], "little")
    unp  = int.from_bytes(buf[0x10:0x14], "little")
    pck  = int.from_bytes(buf[0x14:0x18], "little")
    off  = int.from_bytes(buf[0x18:0x1c], "little")
    f1c  = int.from_bytes(buf[0x1c:0x20], "little")
    fid  = int.from_bytes(buf[0x20:0x24], "little")
    name = buf[0x24:ENTRY_SIZE].split(b"\x00")[0].decode("cp932", errors="replace")
    return dict(ft=ft, unpacked_size=unp, packed_size=pck, offset=off,
                flags=f1c, file_id=fid, name=name)


def build_entry(meta: dict) -> bytes:
    buf = bytearray(ENTRY_SIZE)
    buf[0:8] = SIG_ENTRY
    struct.pack_into("<Q", buf, 0x08, meta["ft"])
    struct.pack_into("<I", buf, 0x10, meta["unpacked_size"])
    struct.pack_into("<I", buf, 0x14, meta["packed_size"])
    struct.pack_into("<I", buf, 0x18, meta["offset"])
    struct.pack_into("<I", buf, 0x1c, meta["flags"])
    struct.pack_into("<I", buf, 0x20, meta["file_id"])
    name_bytes = meta["name"].encode("cp932")
    max_name = ENTRY_SIZE - 0x24
    if len(name_bytes) >= max_name:
        raise ValueError(f"filename too long: {meta['name']!r}")
    buf[0x24:0x24 + len(name_bytes)] = name_bytes
    # rest already zero
    return bytes(buf)


def read_index(data: bytes):
    tail = data[-TAIL_SIZE:]
    if tail[:8] != SIG_TAIL:
        raise ValueError(f"bad tail signature: {tail[:8]!r}")
    entry_count = struct.unpack_from("<I", tail, 0x08)[0]
    index_off   = struct.unpack_from("<I", tail, 0x0C)[0]
    idx_unp     = struct.unpack_from("<I", tail, 0x10)[0]
    idx_pck     = struct.unpack_from("<I", tail, 0x14)[0]
    tail_chk    = struct.unpack_from("<I", tail, 0x18)[0]
    data_sz     = struct.unpack_from("<I", tail, 0x1c)[0]
    build_mark  = struct.unpack_from("<I", tail, 0x20)[0]
    zero        = struct.unpack_from("<I", tail, 0x24)[0]

    if idx_unp != entry_count * ENTRY_SIZE:
        raise ValueError(
            f"index_unpacked={idx_unp:#x} doesn't match entries*0x128="
            f"{entry_count*ENTRY_SIZE:#x}")

    # decompress index _AF1 block
    idx_block = data[index_off:index_off + idx_pck]
    if idx_block[:3] != b"_AF":
        raise ValueError(f"bad index block magic: {idx_block[:3]!r}")
    idx_alg = idx_block[3:4]
    idx_total = int.from_bytes(idx_block[4:6], "little")
    idx_pre   = int.from_bytes(idx_block[6:8], "little")
    idx_out   = int.from_bytes(idx_block[8:10], "little")

    if idx_total != idx_pck:
        raise ValueError(
            f"index block total={idx_total:#x} != packed={idx_pck:#x}")
    if idx_pre != 0:
        raise NotImplementedError(
            "index uses two-stage compression; not encountered in samples yet")

    payload = idx_block[10:idx_total]
    if idx_alg == b"1":
        idx_raw = lzss_decompress_af1(payload, idx_out)
    elif idx_alg == b"0" or (idx_alg != b"1" and idx_alg != b"2"):
        idx_raw = payload[:idx_out]
    elif idx_alg == b"2":
        raise NotImplementedError("_AF2 (Huffman) index not implemented")
    else:
        raise ValueError(f"unknown index alg: {idx_alg!r}")

    if len(idx_raw) != idx_unp:
        raise ValueError(
            f"index decompressed to {len(idx_raw)} bytes; expected {idx_unp}")

    entries = [parse_entry(idx_raw[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE])
               for i in range(entry_count)]

    meta = dict(
        entry_count=entry_count,
        index_offset=index_off,
        index_unpacked_size=idx_unp,
        index_packed_size=idx_pck,
        tail_checksum=tail_chk,
        data_area_size=data_sz,
        build_mark=build_mark,
        tail_zero=zero,
    )
    return entries, meta


# -------- commands --------

def cmd_info(archive_path: str):
    with open(archive_path, "rb") as f:
        data = f.read()
    if data[:8] != SIG_FILE:
        print(f"!! bad file signature: {data[:8]!r}")
        return 1
    entries, meta = read_index(data)
    print(f"archive : {archive_path}")
    print(f"size    : {len(data):,} bytes ({len(data):#x})")
    print(f"entries : {meta['entry_count']}")
    print(f"idx off : {meta['index_offset']:#x}")
    print(f"idx pck : {meta['index_packed_size']:#x}  "
          f"unp : {meta['index_unpacked_size']:#x}")
    print(f"tail_chk: {meta['tail_checksum']:#010x}")
    print(f"data_sz : {meta['data_area_size']:#x}")
    print(f"build   : {meta['build_mark']:#x}  zero: {meta['tail_zero']:#x}")
    print()
    print(f"{'idx':>3s}  {'offset':>10s}  {'packed':>10s}  "
          f"{'unpacked':>10s}  {'file_id':>8s}  {'flags':>10s}  name")
    for i, e in enumerate(entries):
        print(f"{i:3d}  {e['offset']:#010x}  {e['packed_size']:#010x}  "
              f"{e['unpacked_size']:#010x}  {e['file_id']:#08x}  "
              f"{e['flags']:#010x}  {e['name']}")
    # consistency
    cum = 0
    for e in entries:
        if cum != e["offset"]:
            print(f"!! offset mismatch at {e['name']}: "
                  f"stored {e['offset']:#x}, cumulative {cum:#x}")
            break
        cum += e["packed_size"]
    else:
        print(f"offsets: contiguous OK (total {cum:#x})")
    return 0


def cmd_extract(archive_path: str, out_dir: str, decompress: bool = False):
    with open(archive_path, "rb") as f:
        data = f.read()
    if data[:8] != SIG_FILE:
        raise ValueError(f"bad file signature: {data[:8]!r}")
    entries, meta = read_index(data)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # manifest captures every byte needed for bit-perfect repack
    manifest = dict(
        format="lapis_lax",
        version=1,
        source=os.path.basename(archive_path),
        decompressed=bool(decompress),
        tail=dict(
            tail_checksum=meta["tail_checksum"],
            build_mark=meta["build_mark"],
            tail_zero=meta["tail_zero"],
        ),
        entries=[],
    )

    # preserve original _AF1 index block verbatim, so a repack that doesn't
    # touch entry metadata yields a byte-identical archive
    idx_block_raw = data[meta["index_offset"]:
                         meta["index_offset"] + meta["index_packed_size"]]
    with open(out / "index_block.bin", "wb") as f:
        f.write(idx_block_raw)
    manifest["index_block_file"] = "index_block.bin"

    files_dir = out / "files"
    files_dir.mkdir(exist_ok=True)
    if decompress:
        raw_dir = out / "files_raw"
        raw_dir.mkdir(exist_ok=True)

    skipped_decompress = 0

    for i, e in enumerate(entries):
        start = DATA_BASE + e["offset"]
        end   = start + e["packed_size"]
        if end > meta["index_offset"]:
            raise ValueError(
                f"entry {i} ({e['name']}) runs past index start")
        blob = data[start:end]

        # use windows-friendly filename for filesystem;
        # "sce\\0610.te" -> "sce/0610.te"
        safe_name = e["name"].replace("\\", "/")
        out_path = files_dir / safe_name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(blob)

        entry_rec = dict(
            index=i,
            name=e["name"],
            stored_as=safe_name,
            filetime=e["ft"],
            unpacked_size=e["unpacked_size"],
            packed_size=e["packed_size"],
            offset=e["offset"],
            flags=e["flags"],
            file_id=e["file_id"],
        )

        if decompress:
            if e["packed_size"] == 0 and e["unpacked_size"] == 0:
                # zero-byte marker (e.g. sce/v100.id) -- nothing to decompress
                entry_rec["raw_stored_as"] = None
                entry_rec["af_blocks"] = []
            else:
                try:
                    raw, blocks = decompress_af_chain(blob)
                except (NotImplementedError, ValueError) as err:
                    print(f"!! {e['name']}: decompress failed ({err}); "
                          "keeping compressed form only")
                    skipped_decompress += 1
                    entry_rec["raw_stored_as"] = None
                    entry_rec["af_blocks"] = None
                else:
                    if len(raw) != e["unpacked_size"]:
                        print(f"!! {e['name']}: decompressed "
                              f"{len(raw)} != unpacked_size "
                              f"{e['unpacked_size']} (inconsistent)")
                    raw_path = raw_dir / safe_name
                    raw_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(raw_path, "wb") as f:
                        f.write(raw)
                    entry_rec["raw_stored_as"] = safe_name
                    entry_rec["af_blocks"] = blocks

        manifest["entries"].append(entry_rec)

    manifest_path = out / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f"extracted {len(entries)} files to {out}")
    if decompress:
        ok = sum(1 for e in manifest["entries"]
                 if e.get("raw_stored_as") is not None)
        print(f"  decompressed: {ok} / {len(entries)} "
              f"(skipped {skipped_decompress})")
    print(f"manifest: {manifest_path}")
    return 0


def cmd_repack(in_dir: str, archive_path: str, force_recompress: bool = False):
    src = Path(in_dir)
    with open(src / "manifest.json", "r", encoding="utf-8") as f:
        manifest = json.load(f)

    files_dir = src / "files"
    raw_dir   = src / "files_raw"
    decompressed = manifest.get("decompressed", False)

    # pass 1: read payloads, recompute offsets
    payloads = []
    entries_meta = []
    cum = 0
    recompress_count = 0
    reuse_count = 0
    for em in manifest["entries"]:
        compressed_path = files_dir / em["stored_as"]
        raw_path = None
        if decompressed and em.get("raw_stored_as"):
            raw_path = raw_dir / em["raw_stored_as"]

        use_recompress = False
        if raw_path and raw_path.exists():
            raw_size = raw_path.stat().st_size
            if force_recompress or raw_size != em["unpacked_size"]:
                use_recompress = True

        if use_recompress:
            raw = raw_path.read_bytes()
            block_sizes = None
            if em.get("af_blocks") and not force_recompress:
                # honor original chunking only if raw size matches
                declared = sum(b["output_size"] for b in em["af_blocks"])
                if declared == len(raw):
                    block_sizes = [b["output_size"] for b in em["af_blocks"]]
            blob = compress_af_chain(raw, block_sizes=block_sizes)
            new_unpacked = len(raw)
            recompress_count += 1
        else:
            if not compressed_path.exists():
                raise FileNotFoundError(
                    f"{em['name']}: neither raw nor compressed form on disk")
            blob = compressed_path.read_bytes()
            if len(blob) != em["packed_size"]:
                print(f"!! {em['name']}: compressed size {len(blob)} != "
                      f"manifest packed_size {em['packed_size']} -- "
                      f"using actual size")
            new_unpacked = em["unpacked_size"]
            reuse_count += 1

        pck = len(blob)
        entries_meta.append(dict(
            ft=em["filetime"],
            unpacked_size=new_unpacked,
            packed_size=pck,
            offset=cum,
            flags=em["flags"],
            file_id=em["file_id"],
            name=em["name"],
        ))
        payloads.append(blob)
        cum += pck

    # build data area
    data_area = b"".join(payloads)
    index_offset = DATA_BASE + len(data_area)

    # build index (raw) then LZSS-wrap into _AF1 block
    idx_raw = b"".join(build_entry(m) for m in entries_meta)
    if len(idx_raw) != len(entries_meta) * ENTRY_SIZE:
        raise AssertionError("built index size mismatch")

    # Bit-perfect path: if we saved the original index block during extract
    # AND it decompresses to exactly our freshly-built index bytes, reuse it.
    idx_block = None
    idx_block_file = manifest.get("index_block_file")
    if idx_block_file:
        raw_idx_path = src / idx_block_file
        if raw_idx_path.exists():
            cand = raw_idx_path.read_bytes()
            if (len(cand) >= 10 and cand[:3] == b"_AF"
                    and cand[3:4] == b"1"
                    and int.from_bytes(cand[4:6], "little") == len(cand)
                    and int.from_bytes(cand[6:8], "little") == 0):
                cand_out = lzss_decompress_af1(
                    cand[10:], int.from_bytes(cand[8:10], "little"))
                if cand_out == idx_raw:
                    idx_block = cand
                    print("  index: reused original _AF1 block (bit-perfect)")

    if idx_block is None:
        idx_block = build_af1_block(idx_raw)
        print("  index: rebuilt via our LZSS (semantically identical)")

    # tail
    tail = bytearray(TAIL_SIZE)
    tail[0:8] = SIG_TAIL
    struct.pack_into("<I", tail, 0x08, len(entries_meta))
    struct.pack_into("<I", tail, 0x0C, index_offset)
    struct.pack_into("<I", tail, 0x10, len(idx_raw))
    struct.pack_into("<I", tail, 0x14, len(idx_block))
    struct.pack_into("<I", tail, 0x18, manifest["tail"]["tail_checksum"])
    struct.pack_into("<I", tail, 0x1c, len(data_area))   # data_area_size
    struct.pack_into("<I", tail, 0x20, manifest["tail"]["build_mark"])
    struct.pack_into("<I", tail, 0x24, manifest["tail"]["tail_zero"])

    with open(archive_path, "wb") as f:
        f.write(SIG_FILE)
        f.write(data_area)
        f.write(idx_block)
        f.write(bytes(tail))

    print(f"wrote {archive_path}")
    print(f"  entries: {len(entries_meta)} "
          f"(reused {reuse_count}, recompressed {recompress_count})")
    print(f"  data  : {len(data_area):,} bytes (@0x8 .. {index_offset:#x})")
    print(f"  index : {len(idx_block):,} bytes packed / "
          f"{len(idx_raw):,} unpacked")
    return 0


# -------- standalone file helpers --------

def cmd_unpack_file(in_path: str, out_path: str):
    """Decompress one loose file (chain of _AF blocks) to raw bytes."""
    with open(in_path, "rb") as f:
        data = f.read()
    raw, blocks = decompress_af_chain(data)
    with open(out_path, "wb") as f:
        f.write(raw)
    print(f"decompressed {in_path} ({len(data)} B) -> "
          f"{out_path} ({len(raw)} B, {len(blocks)} _AF blocks)")
    for i, b in enumerate(blocks):
        print(f"  block {i}: alg='{b['alg']}' "
              f"out={b['output_size']:#x} total={b['total_size']:#x}")
    return 0


def cmd_pack_file(in_path: str, out_path: str):
    """Compress one raw file into an _AF1 chain (chunked by 0x8000)."""
    with open(in_path, "rb") as f:
        raw = f.read()
    blob = compress_af_chain(raw)
    with open(out_path, "wb") as f:
        f.write(blob)
    print(f"compressed {in_path} ({len(raw)} B) -> "
          f"{out_path} ({len(blob)} B)")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Lapis LAX archive tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="print archive info + entry list")
    p_info.add_argument("archive")

    p_ex = sub.add_parser("extract", help="unpack archive")
    p_ex.add_argument("archive")
    p_ex.add_argument("out_dir")
    p_ex.add_argument("-d", "--decompress", action="store_true",
                      help="also decompress each file's _AF chain into "
                           "files_raw/ (usable for editing)")

    p_rp = sub.add_parser("repack", help="rebuild archive from extracted dir")
    p_rp.add_argument("in_dir")
    p_rp.add_argument("archive")
    p_rp.add_argument("--recompress", action="store_true",
                      help="force recompression from files_raw/ even when "
                           "raw size is unchanged (useful if you edited in "
                           "place without changing length)")

    p_df = sub.add_parser("unpack-file", help="decompress a single _AF-chain "
                                              "file (e.g. extracted .te)")
    p_df.add_argument("in_path")
    p_df.add_argument("out_path")

    p_cf = sub.add_parser("pack-file", help="compress a single raw file "
                                            "into an _AF1 chain")
    p_cf.add_argument("in_path")
    p_cf.add_argument("out_path")

    args = ap.parse_args()
    if args.cmd == "info":
        return cmd_info(args.archive)
    if args.cmd == "extract":
        return cmd_extract(args.archive, args.out_dir,
                           decompress=args.decompress)
    if args.cmd == "repack":
        return cmd_repack(args.in_dir, args.archive,
                          force_recompress=args.recompress)
    if args.cmd == "unpack-file":
        return cmd_unpack_file(args.in_path, args.out_path)
    if args.cmd == "pack-file":
        return cmd_pack_file(args.in_path, args.out_path)


if __name__ == "__main__":
    sys.exit(main() or 0)
