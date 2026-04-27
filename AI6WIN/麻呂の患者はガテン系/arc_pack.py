"""
AI6WIN / AI5WIN ARC packer.

Reads __arc_index.json to preserve the original order, filenames, and size
fields. Payloads are written verbatim — no LZSS. When a payload's on-disk
size differs from what the JSON recorded, the tool assumes the file was
rewritten as plaintext (e.g. by a text-injection pipeline) and updates both
compressed_size and uncompressed_size to the new length, so the engine
skips its LZSS path and consumes the bytes directly.

Usage:
    python arc_pack.py <in_dir> <out.arc>        # needs __arc_index.json
    python arc_pack.py <in_dir> <out.arc> --raw  # from scratch, no JSON
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from arc_codec import (
    ENTRY_TOTAL_SIZE,
    HEADER_SIZE,
    encrypt_filename,
    pack_entry_meta,
    pack_header,
)

INDEX_JSON = "__arc_index.json"


def _load_manifest(src: Path) -> list[dict]:
    path = src / INDEX_JSON
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found; use --raw to pack without a manifest"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _scan_dir(src: Path) -> list[dict]:
    """Build a manifest from scratch by walking src in sorted order."""
    entries: list[dict] = []
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        if path.name == INDEX_JSON:
            continue
        name = str(path.relative_to(src)).replace(os.sep, "/")
        size = path.stat().st_size
        entries.append({
            "filename": name,
            "compressed_size": size,
            "uncompressed_size": size,
        })
    return entries


def _read_and_resolve(
    src: Path,
    manifest: list[dict],
    verbose: bool,
) -> tuple[list[dict], list[bytes]]:
    """Load every payload and finalize size fields.

    Rule: if on-disk size differs from manifest's compressed_size, the file
    has been rewritten. Treat it as plaintext: set both size fields to the
    Each entry's compressed_size / uncompressed_size come straight from the
    manifest. If the file on disk does not match compressed_size, that means
    someone rewrote the .mes without updating the manifest — we treat that
    as a hard error rather than silently re-labelling the entry, because
    guessing is what led to broken archives before mes_inject started
    writing fake-LZSS streams with correct size fields.
    """
    blobs: list[bytes] = []
    resolved: list[dict] = []

    for item in manifest:
        name = item["filename"]
        disk = src / name.replace("\\", "/")
        if not disk.is_file():
            raise FileNotFoundError(f"manifest file missing on disk: {name}")
        data = disk.read_bytes()
        size = len(data)

        orig_comp = item["compressed_size"]
        orig_uncomp = item["uncompressed_size"]

        if size != orig_comp:
            raise ValueError(
                f"{name}: on-disk size {size} != manifest compressed_size {orig_comp}. "
                f"If you rewrote this file, also update its compressed_size / "
                f"uncompressed_size in __arc_index.json (mes_inject does this "
                f"automatically when invoked via its batch -o mode)."
            )

        resolved.append({
            "filename": name,
            "compressed_size": orig_comp,
            "uncompressed_size": orig_uncomp,
        })
        blobs.append(data)

    return resolved, blobs


def pack(
    src: Path,
    out: Path,
    *,
    raw: bool = False,
    verbose: bool = True,
) -> None:
    if raw:
        manifest = _scan_dir(src)
        if verbose:
            print(f"raw mode: scanned {len(manifest)} files from {src}")
    else:
        manifest = _load_manifest(src)
        if verbose:
            print(f"manifest: {len(manifest)} entries from {INDEX_JSON}")

    if not manifest:
        raise ValueError(f"nothing to pack in {src}")

    resolved, blobs = _read_and_resolve(src, manifest, verbose=verbose)

    count = len(resolved)
    data_start = HEADER_SIZE + count * ENTRY_TOTAL_SIZE

    # Compute per-entry offsets in one pass.
    offsets: list[int] = []
    cur = data_start
    for blob in blobs:
        offsets.append(cur)
        cur += len(blob)
    total = cur

    with open(out, "wb") as f:
        f.write(pack_header(count))
        for entry, off in zip(resolved, offsets):
            f.write(encrypt_filename(entry["filename"]))
            f.write(pack_entry_meta(
                entry["compressed_size"],
                entry["uncompressed_size"],
                off,
            ))
        for blob in blobs:
            f.write(blob)

    if verbose:
        md5 = hashlib.md5()
        with open(out, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                md5.update(chunk)
        print(f"\nwrote {out}  ({count} entries, {total} bytes)")
        print(f"md5: {md5.hexdigest()}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Pack a directory into an AI6WIN / AI5WIN .arc archive"
    )
    p.add_argument("src", help="Directory produced by arc_extract.py")
    p.add_argument("out", help="Output .arc path")
    p.add_argument(
        "--raw",
        action="store_true",
        help="Ignore __arc_index.json; pack every file as plaintext entry",
    )
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args(argv)

    src = Path(args.src)
    if not src.is_dir():
        p.error(f"not a directory: {src}")

    pack(src, Path(args.out), raw=args.raw, verbose=not args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
