#!/usr/bin/env python3
"""
Interlude Engine SCR Script — Text Extractor
=============================================
Target: インタールード (Interlude) / さよならを教えて etc.
Format: SCR:0001
Output: GalTransl-compatible JSON

File layout:
  [0x00-0x07]  Magic "SCR:0001"
  [0x08-0x0F]  Script name (8B, null-padded)
  [0x10-0x13]  uint32 bytecode_size
  [0x14 ...]   Bytecode instructions  (func_id:u8, size:u8, params...)
  [+bc_size]   uint32 text_data_size
  [+bc_size+4] Text data (XOR 0x7F encrypted, CP932, null-separated)

Instruction 0x5E (size=20): Text display
  +2  uint16 message_id
  +4  uint16 reserved (0)
  +6  uint16 flags (bit0=append, bit9=paragraph_end)
  +8  uint16 x_pos
  +10 uint16 y_pos
  +12 uint32 voice_offset (0xFFFFFFFF = no voice)
  +16 uint32 text_offset

Usage: python scr_extract.py <input.scr> [output.json]
"""

import struct
import json
import sys
import os

# ─── Constants ───────────────────────────────────────────────────────────────

MAGIC = b"SCR:0001"
HEADER_SIZE = 0x14       # 20 bytes: magic(8) + name(8) + bc_size(4)
XOR_KEY = 0x7F
TEXT_OPCODE = 0x5E
TEXT_INSTR_SIZE = 0x14   # 20 bytes

# ─── Core Functions ──────────────────────────────────────────────────────────

def parse_scr(data: bytes) -> dict:
    """Parse SCR file, return structured data."""
    # Validate magic
    if data[:8] != MAGIC:
        raise ValueError(f"Bad magic: {data[:8]!r}, expected {MAGIC!r}")

    # Header
    name_raw = data[8:16]
    name = name_raw.split(b"\x00")[0].decode("ascii")
    bc_size = struct.unpack_from("<I", data, 0x10)[0]

    bc_start = HEADER_SIZE
    bc_end = bc_start + bc_size

    # Text section
    text_size = struct.unpack_from("<I", data, bc_end)[0]
    text_data_off = bc_end + 4
    text_enc = data[text_data_off : text_data_off + text_size]
    text_dec = bytes(b ^ XOR_KEY for b in text_enc)

    # Build string table: offset -> raw bytes
    str_table = {}
    pos = 0
    while pos < len(text_dec):
        end = text_dec.find(b"\x00", pos)
        if end == -1:
            end = len(text_dec)
        if end > pos:
            str_table[pos] = text_dec[pos:end]
        pos = end + 1

    return {
        "name": name,
        "bc_start": bc_start,
        "bc_end": bc_end,
        "bc_size": bc_size,
        "text_data_off": text_data_off,
        "text_size": text_size,
        "text_dec": text_dec,
        "str_table": str_table,
    }


def extract_text_entries(data: bytes, scr: dict) -> list[dict]:
    """Extract all 0x5E text display instructions."""
    entries = []
    pos = scr["bc_start"]
    bc_end = scr["bc_end"]
    str_table = scr["str_table"]
    text_dec = scr["text_dec"]
    idx = 0

    while pos < bc_end:
        func_id = data[pos]
        size = data[pos + 1]
        if size == 0:
            break

        if func_id == TEXT_OPCODE and size == TEXT_INSTR_SIZE:
            msg_id = struct.unpack_from("<H", data, pos + 2)[0]
            flags = struct.unpack_from("<H", data, pos + 6)[0]
            x_pos = struct.unpack_from("<H", data, pos + 8)[0]
            y_pos = struct.unpack_from("<H", data, pos + 10)[0]
            voice_off = struct.unpack_from("<I", data, pos + 12)[0]
            text_off = struct.unpack_from("<I", data, pos + 16)[0]

            # Decode voice filename
            voice = None
            if voice_off != 0xFFFFFFFF and voice_off in str_table:
                voice = str_table[voice_off].decode("ascii", errors="replace")

            # Decode text
            text_raw = str_table.get(text_off, b"")
            text = text_raw.lstrip(b"\x20").decode("cp932", errors="replace")

            # Determine name from voice file pattern
            # Voice files like ouk_094 -> character桜花, etc.
            # We don't have a mapping, so leave name based on voice presence
            name = voice if voice else ""

            entry = {
                "id": idx,
                "msg_id": f"0x{msg_id:04X}",
                "name": name,
                "message": text,
                # Metadata for inject
                "_instr_addr": pos,
                "_flags": f"0x{flags:04X}",
                "_voice_off": voice_off,
                "_text_off": text_off,
            }
            entries.append(entry)
            idx += 1

        pos += size

    return entries


def save_json(entries: list[dict], output_path: str):
    """Save entries as GalTransl-compatible JSON."""
    # GalTransl format: list of {name, message, id}
    gt_entries = []
    for e in entries:
        gt_entry = {
            "id": e["id"],
            "name": e["name"],
            "message": e["message"],
        }
        # Preserve metadata as extra fields
        gt_entry["msg_id"] = e["msg_id"]
        gt_entry["_flags"] = e["_flags"]
        gt_entries.append(gt_entry)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(gt_entries, f, ensure_ascii=False, indent=2)


# ─── Main ────────────────────────────────────────────────────────────────────

def process_one(input_path: str, output_path: str):
    """Extract text from a single SCR file."""
    data = open(input_path, "rb").read()
    scr = parse_scr(data)

    entries = extract_text_entries(data, scr)
    voiced = sum(1 for e in entries if e["name"])
    print(f"  {os.path.basename(input_path)}: {len(entries)} entries "
          f"({voiced} voiced, {len(entries)-voiced} narration) "
          f"-> {os.path.basename(output_path)}")

    save_json(entries, output_path)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.scr | input_dir> [output.json | output_dir]")
        print()
        print("  Single file:  scr_extract.py a_004.scr [a_004.json]")
        print("  Batch:        scr_extract.py ./scr_folder/ [./json_output/]")
        print()
        print("  When input is a directory, extracts all *.scr files inside it.")
        sys.exit(1)

    input_path = sys.argv[1]

    # ── Directory (batch) mode ──
    if os.path.isdir(input_path):
        scr_files = sorted(
            f for f in os.listdir(input_path)
            if f.lower().endswith(".scr")
        )
        if not scr_files:
            print(f"No .scr files found in {input_path}")
            sys.exit(1)

        out_dir = sys.argv[2] if len(sys.argv) >= 3 else input_path
        os.makedirs(out_dir, exist_ok=True)

        print(f"Batch extract: {len(scr_files)} files from {input_path}")
        ok = 0
        for fname in scr_files:
            src = os.path.join(input_path, fname)
            dst = os.path.join(out_dir, os.path.splitext(fname)[0] + ".json")
            try:
                process_one(src, dst)
                ok += 1
            except Exception as e:
                print(f"  {fname}: ERROR - {e}")
        print(f"\nDone: {ok}/{len(scr_files)} succeeded")
        return

    # ── Single file mode ──
    if not os.path.isfile(input_path):
        print(f"Error: {input_path} is not a file or directory")
        sys.exit(1)

    if len(sys.argv) >= 3:
        output_path = sys.argv[2]
    else:
        base = os.path.splitext(os.path.basename(input_path))[0]
        output_path = base + ".json"

    process_one(input_path, output_path)
    print("Done")


if __name__ == "__main__":
    main()
