"""
AI6WIN / AI5WIN ARC extractor.

Writes every payload as the exact bytes stored in the archive (no LZSS
decompression). A sidecar __arc_index.json records compressed_size and
uncompressed_size so the packer can round-trip byte-for-byte.

Works for mes.arc, layer.arc, data.arc, movie.arc, music.arc — every archive
the engine loads with the Silky AI5/AI6 code path shares this format.

Usage:
    python arc_extract.py <archive.arc> [-o <out_dir>]
    python arc_extract.py <archive.arc> --list
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from arc_codec import (
    ENTRY_META_SIZE,
    ENTRY_NAME_SIZE,
    ENTRY_TOTAL_SIZE,
    HEADER_SIZE,
    MAX_ENTRIES,
    decrypt_filename,
    unpack_entry_meta,
    unpack_header,
)

INDEX_JSON = "__arc_index.json"


def read_index(f) -> list[dict]:
    """Parse archive header + index. Returns list of entry dicts."""
    f.seek(0)
    header = f.read(HEADER_SIZE)
    if len(header) < HEADER_SIZE:
        raise ValueError("file too small for header")
    count = unpack_header(header)
    if count == 0 or count > MAX_ENTRIES:
        raise ValueError(f"unreasonable entry count: {count}")

    entries: list[dict] = []
    for i in range(count):
        name_buf = f.read(ENTRY_NAME_SIZE)
        meta_buf = f.read(ENTRY_META_SIZE)
        if len(name_buf) < ENTRY_NAME_SIZE or len(meta_buf) < ENTRY_META_SIZE:
            raise ValueError(f"index truncated at entry {i}")

        comp, uncomp, off = unpack_entry_meta(meta_buf)
        try:
            name = decrypt_filename(name_buf)
        except Exception as e:
            # Keep going but flag the entry; skipping loses positional alignment.
            name = f"__decrypt_failed_{i:04d}.bin"
            print(f"  [WARN] entry {i}: filename decrypt failed ({e})", file=sys.stderr)

        entries.append({
            "filename": name,
            "compressed_size": comp,
            "uncompressed_size": uncomp,
            "offset": off,
        })
    return entries


def validate_entries(entries: list[dict], file_size: int) -> None:
    """Sanity-check offsets and sizes against the archive's actual size."""
    count = len(entries)
    data_start = HEADER_SIZE + count * ENTRY_TOTAL_SIZE
    for i, e in enumerate(entries):
        if e["offset"] < data_start:
            raise ValueError(
                f"entry {i} ({e['filename']!r}): offset {e['offset']:#x} < "
                f"data start {data_start:#x}"
            )
        if e["offset"] + e["compressed_size"] > file_size:
            raise ValueError(
                f"entry {i} ({e['filename']!r}): extends past EOF "
                f"({e['offset']:#x}+{e['compressed_size']:#x} > {file_size:#x})"
            )


def extract(arc_path: Path, out_dir: Path, verbose: bool = True) -> int:
    """Extract every entry verbatim. Returns entry count."""
    file_size = arc_path.stat().st_size
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(arc_path, "rb") as f:
        entries = read_index(f)
        validate_entries(entries, file_size)

        data_start = HEADER_SIZE + len(entries) * ENTRY_TOTAL_SIZE
        if verbose:
            print(f"archive:      {arc_path}")
            print(f"entries:      {len(entries)}")
            print(f"index end:    {data_start:#x}")
            print(f"file size:    {file_size:#x}")

        meta_list = []
        for i, e in enumerate(entries):
            name = e["filename"]
            # Normalize directory separators, but preserve case.
            safe = name.replace("\\", "/")
            if ".." in safe.split("/"):
                raise ValueError(f"path traversal in name: {name!r}")

            out_path = out_dir / safe
            out_path.parent.mkdir(parents=True, exist_ok=True)

            f.seek(e["offset"])
            data = f.read(e["compressed_size"])
            if len(data) != e["compressed_size"]:
                raise IOError(
                    f"{name}: short read ({len(data)}/{e['compressed_size']})"
                )
            out_path.write_bytes(data)

            meta_list.append({
                "filename": name,
                "compressed_size": e["compressed_size"],
                "uncompressed_size": e["uncompressed_size"],
            })
            if verbose:
                tag = "LZSS" if e["compressed_size"] != e["uncompressed_size"] else "raw "
                print(
                    f"  [{i+1:>3}/{len(entries)}] {name:<38}  "
                    f"comp={e['compressed_size']:>8}  "
                    f"raw={e['uncompressed_size']:>8}  ({tag})"
                )

    (out_dir / INDEX_JSON).write_text(
        json.dumps(meta_list, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if verbose:
        print(f"\ndone: {len(entries)} files -> {out_dir}")
        print(f"index json: {out_dir / INDEX_JSON}")
    return len(entries)


def list_only(arc_path: Path) -> None:
    """Print the index without writing anything."""
    with open(arc_path, "rb") as f:
        entries = read_index(f)
    total_c = sum(e["compressed_size"] for e in entries)
    total_u = sum(e["uncompressed_size"] for e in entries)
    print(f"# {arc_path.name}: {len(entries)} entries")
    print(f"# total compressed={total_c}, uncompressed={total_u}")
    print(f"# {'idx':>3}  {'filename':<40}  {'comp':>9}  {'raw':>9}  "
          f"{'offset':>10}  lzss")
    for i, e in enumerate(entries):
        mark = "*" if e["compressed_size"] != e["uncompressed_size"] else " "
        print(
            f"  {i:>3}  {e['filename']:<40}  "
            f"{e['compressed_size']:>9}  {e['uncompressed_size']:>9}  "
            f"{e['offset']:>10}  {mark}"
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Extract AI6WIN / AI5WIN .arc archives")
    p.add_argument("archive")
    p.add_argument("-o", "--out", help="Output directory (default: <arc>_unpacked)")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--list", action="store_true", help="Print index only, no extract")
    args = p.parse_args(argv)

    arc = Path(args.archive)
    if not arc.is_file():
        p.error(f"archive not found: {arc}")

    if args.list:
        list_only(arc)
        return 0

    out_dir = Path(args.out) if args.out else arc.with_name(arc.stem + "_unpacked")
    extract(arc, out_dir, verbose=not args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
