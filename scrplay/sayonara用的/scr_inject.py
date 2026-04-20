#!/usr/bin/env python3
"""
Interlude Engine SCR Script — Text Injector
============================================
Target: インタールード (Interlude) / さよならを教えて etc.
Format: SCR:0001

Rebuilds text area from translated JSON and patches all offset references
in the bytecode area.

Strategy:
  1. Parse original SCR → bytecode + text area
  2. Load translated JSON (GalTransl format: id/name/message)
  3. Rebuild text area with new strings (keeping original order & encoding)
  4. Build old_offset → new_offset mapping
  5. Patch all text offset references in bytecode
  6. Update text_size field
  7. Write new SCR

Usage: python scr_inject.py <original.scr> <translated.json> [output.scr]
"""

import struct
import json
import sys
import os

# ─── Constants ───────────────────────────────────────────────────────────────

MAGIC = b"SCR:0001"
HEADER_SIZE = 0x14
XOR_KEY = 0x7F
TEXT_OPCODE = 0x5E
TEXT_INSTR_SIZE = 0x14

# ─── Encoding ────────────────────────────────────────────────────────────────

def encode_text(text: str, encoding: str = "cp932") -> bytes:
    """Encode text string to target encoding.

    For Chinese translation (GBK), change encoding to 'gbk'.
    The leading space is part of narration formatting — re-add if present
    in original but stripped during extract.
    """
    return text.encode(encoding, errors="replace")


# ─── SCR Parsing ─────────────────────────────────────────────────────────────

def parse_scr(data: bytes) -> dict:
    """Parse original SCR file structure."""
    if data[:8] != MAGIC:
        raise ValueError(f"Bad magic: {data[:8]!r}")

    name = data[8:16].split(b"\x00")[0].decode("ascii")
    bc_size = struct.unpack_from("<I", data, 0x10)[0]
    bc_start = HEADER_SIZE
    bc_end = bc_start + bc_size

    text_size = struct.unpack_from("<I", data, bc_end)[0]
    text_data_off = bc_end + 4
    text_enc = data[text_data_off : text_data_off + text_size]
    text_dec = bytes(b ^ XOR_KEY for b in text_enc)

    # Build ordered string list: [(offset, raw_bytes), ...]
    str_list = []
    pos = 0
    while pos < len(text_dec):
        end = text_dec.find(b"\x00", pos)
        if end == -1:
            end = len(text_dec)
        if end > pos:
            str_list.append((pos, text_dec[pos:end]))
        pos = end + 1

    return {
        "name": name,
        "data": data,
        "header": data[:HEADER_SIZE],
        "bytecode": bytearray(data[bc_start:bc_end]),
        "bc_start": bc_start,
        "bc_end": bc_end,
        "bc_size": bc_size,
        "text_dec": text_dec,
        "str_list": str_list,
    }


def collect_text_entries(data: bytes, scr: dict) -> list[dict]:
    """Collect all 0x5E text entries with their original offsets."""
    entries = []
    pos = scr["bc_start"]
    bc_end = scr["bc_end"]
    idx = 0

    while pos < bc_end:
        func_id = data[pos]
        size = data[pos + 1]
        if size == 0:
            break

        if func_id == TEXT_OPCODE and size == TEXT_INSTR_SIZE:
            voice_off = struct.unpack_from("<I", data, pos + 12)[0]
            text_off = struct.unpack_from("<I", data, pos + 16)[0]
            entries.append({
                "idx": idx,
                "addr": pos,
                "voice_off": voice_off,
                "text_off": text_off,
            })
            idx += 1

        pos += size

    return entries


def collect_all_refs(data: bytes, scr: dict) -> list[tuple]:
    """Collect ALL text offset references from bytecode.

    Returns list of (absolute_file_offset, current_text_offset).
    This covers 0x5E instruction refs AND all other instruction refs.
    """
    refs = []
    str_offsets = set(off for off, _ in scr["str_list"])
    pos = scr["bc_start"]
    bc_end = scr["bc_end"]

    while pos < bc_end:
        func_id = data[pos]
        size = data[pos + 1]
        if size == 0:
            break

        if func_id == TEXT_OPCODE and size == TEXT_INSTR_SIZE:
            # Voice offset at +12
            voice_off = struct.unpack_from("<I", data, pos + 12)[0]
            if voice_off != 0xFFFFFFFF and voice_off in str_offsets:
                refs.append((pos + 12, voice_off))
            # Text offset at +16
            text_off = struct.unpack_from("<I", data, pos + 16)[0]
            if text_off in str_offsets:
                refs.append((pos + 16, text_off))
        else:
            # Scan uint32 params at aligned offsets
            for poff in range(2, size - 3):
                val = struct.unpack_from("<I", data, pos + poff)[0]
                if val in str_offsets and val != 0xFFFFFFFF:
                    refs.append((pos + poff, val))

        pos += size

    return refs


# ─── Rebuild ─────────────────────────────────────────────────────────────────

def rebuild_text_area(
    scr: dict,
    translations: dict[int, str],
    encoding: str = "cp932",
) -> tuple[bytes, dict[int, int]]:
    """Rebuild text area with translated strings.

    Args:
        scr: Parsed SCR structure
        translations: {text_entry_idx: translated_message}  (0-based 5E index)
        encoding: Target text encoding

    Returns:
        (new_text_data_decrypted, old_offset_to_new_offset_map)
    """
    # Map original text_off → 5E entry index (for applying translations)
    text_entries = collect_text_entries(scr["data"], scr)
    text_off_to_idx = {}
    for e in text_entries:
        text_off_to_idx[e["text_off"]] = e["idx"]

    # Rebuild string pool preserving original order
    new_parts = []
    offset_map = {}  # old_offset → new_offset
    current_pos = 0

    for old_off, old_raw in scr["str_list"]:
        offset_map[old_off] = current_pos

        # Check if this string has a translation
        entry_idx = text_off_to_idx.get(old_off)
        if entry_idx is not None and entry_idx in translations:
            new_text = translations[entry_idx]
            # Preserve leading space if original had one
            if old_raw.startswith(b"\x20") and not new_text.startswith(" "):
                new_text = " " + new_text
            new_raw = encode_text(new_text, encoding)
        else:
            # Keep original (resource names, untranslated text, etc.)
            new_raw = old_raw

        new_parts.append(new_raw)
        current_pos += len(new_raw) + 1  # +1 for null terminator

    # Build contiguous text data
    new_text = bytearray()
    for part in new_parts:
        new_text.extend(part)
        new_text.append(0x00)

    return bytes(new_text), offset_map


def patch_bytecode(scr: dict, offset_map: dict[int, int]) -> bytearray:
    """Patch all text offset references in bytecode."""
    data = scr["data"]
    bc = bytearray(scr["bytecode"])
    bc_start = scr["bc_start"]

    refs = collect_all_refs(data, scr)

    patched = 0
    for file_off, old_text_off in refs:
        if old_text_off in offset_map:
            new_off = offset_map[old_text_off]
            # Convert file offset to bytecode-relative offset
            bc_off = file_off - bc_start
            struct.pack_into("<I", bc, bc_off, new_off)
            patched += 1
        else:
            print(f"  WARNING: text offset 0x{old_text_off:X} at file 0x{file_off:X} "
                  f"not in offset map!")

    print(f"  Patched {patched}/{len(refs)} references")
    return bc


def write_scr(scr: dict, new_bc: bytearray, new_text_dec: bytes, output_path: str):
    """Write rebuilt SCR file."""
    # Encrypt text data
    new_text_enc = bytes(b ^ XOR_KEY for b in new_text_dec)
    new_text_size = len(new_text_enc)

    out = bytearray()
    # Header (unchanged)
    out.extend(scr["header"])
    # Bytecode (patched)
    out.extend(new_bc)
    # Text size field
    out.extend(struct.pack("<I", new_text_size))
    # Encrypted text data
    out.extend(new_text_enc)

    with open(output_path, "wb") as f:
        f.write(out)

    return len(out)


# ─── Main ────────────────────────────────────────────────────────────────────

def process_one(scr_path: str, json_path: str, output_path: str, encoding: str):
    """Inject translation into a single SCR file."""
    data = open(scr_path, "rb").read()
    scr = parse_scr(data)

    with open(json_path, "r", encoding="utf-8") as f:
        json_data = json.load(f, strict=False)

    translations = {entry["id"]: entry["message"] for entry in json_data}

    new_text, offset_map = rebuild_text_area(scr, translations, encoding)
    delta = len(new_text) - len(scr["text_dec"])
    new_bc = patch_bytecode(scr, offset_map)
    out_size = write_scr(scr, new_bc, new_text, output_path)

    print(f"  {os.path.basename(scr_path)}: {len(translations)} entries, "
          f"text {delta:+d}B -> {os.path.basename(output_path)}")


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <scr | scr_dir> <json | json_dir> [output_dir] [-gbk]")
        print()
        print("  Single:  scr_inject.py a_004.scr a_004.json [a_004_patched.scr]")
        print("  Batch:   scr_inject.py ./scr_orig/ ./json_translated/ [./scr_output/]")
        print()
        print("  -gbk     Use GBK encoding for Chinese patches (default: CP932)")
        print()
        print("  Batch mode matches files by name: a_004.scr <-> a_004.json")
        sys.exit(1)

    # Parse -gbk flag
    args = [a for a in sys.argv[1:] if a != "-gbk"]
    encoding = "gbk" if "-gbk" in sys.argv else "cp932"

    input_path = args[0]
    json_path = args[1]
    output_path = args[2] if len(args) >= 3 else None

    # ── Directory (batch) mode ──
    if os.path.isdir(input_path):
        if not os.path.isdir(json_path):
            print(f"Error: when input is a directory, JSON path must also be a directory")
            sys.exit(1)

        scr_files = sorted(
            f for f in os.listdir(input_path)
            if f.lower().endswith(".scr")
        )
        if not scr_files:
            print(f"No .scr files found in {input_path}")
            sys.exit(1)

        out_dir = output_path if output_path else os.path.join(input_path, "patched")
        os.makedirs(out_dir, exist_ok=True)

        print(f"Batch inject: {len(scr_files)} SCR files, encoding={encoding}")
        ok = 0
        skip = 0
        for fname in scr_files:
            base = os.path.splitext(fname)[0]
            json_file = os.path.join(json_path, base + ".json")
            if not os.path.isfile(json_file):
                skip += 1
                continue
            src = os.path.join(input_path, fname)
            dst = os.path.join(out_dir, fname)
            try:
                process_one(src, json_file, dst, encoding)
                ok += 1
            except Exception as e:
                print(f"  {fname}: ERROR - {e}")

        print(f"\nDone: {ok} injected, {skip} skipped (no JSON)")
        return

    # ── Single file mode ──
    if not os.path.isfile(input_path):
        print(f"Error: {input_path} is not a file or directory")
        sys.exit(1)

    if output_path is None:
        base = os.path.splitext(input_path)[0]
        output_path = base + "_patched.scr"

    process_one(input_path, json_path, output_path, encoding)
    print("Done")


if __name__ == "__main__":
    main()
