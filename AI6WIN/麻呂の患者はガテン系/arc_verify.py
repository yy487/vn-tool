"""
Round-trip verifier for AI6WIN / AI5WIN .arc archives.

Extracts to a temp dir, packs back, and compares the result to the original
byte-for-byte. Because neither the extractor nor the packer touches LZSS,
the comparison should be MD5-identical for any archive.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from pathlib import Path

from arc_extract import extract
from arc_pack import pack


def _md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(arc_path: Path, verbose: bool = True) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        unpacked = tmp_path / "unpacked"
        repacked = tmp_path / "repacked.arc"

        if verbose:
            print(f"[1/3] extract  {arc_path}")
        extract(arc_path, unpacked, verbose=False)

        if verbose:
            print(f"[2/3] pack     -> {repacked}")
        pack(unpacked, repacked, verbose=False)

        if verbose:
            print(f"[3/3] compare")
        original_md5 = _md5(arc_path)
        repacked_md5 = _md5(repacked)
        size_orig = arc_path.stat().st_size
        size_new = repacked.stat().st_size

        if original_md5 == repacked_md5:
            print(f"PASS: byte-perfect round-trip ({size_orig} bytes, md5={original_md5})")
            return True

        # Diff details
        print(f"FAIL: md5 differs")
        print(f"  original: {size_orig} bytes  md5={original_md5}")
        print(f"  repacked: {size_new} bytes  md5={repacked_md5}")
        a = arc_path.read_bytes()
        b = repacked.read_bytes()
        n = min(len(a), len(b))
        for i in range(n):
            if a[i] != b[i]:
                ctx = 16
                lo = max(0, i - ctx)
                print(f"  first diff at {i:#x}")
                print(f"  orig: {a[lo:lo+ctx*2].hex(' ')}")
                print(f"  new:  {b[lo:lo+ctx*2].hex(' ')}")
                break
        else:
            if len(a) != len(b):
                print(f"  identical prefix, lengths differ at {n:#x}")
        return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Round-trip verify an AI6WIN / AI5WIN .arc")
    p.add_argument("archive")
    args = p.parse_args(argv)
    arc = Path(args.archive)
    if not arc.is_file():
        p.error(f"not a file: {arc}")
    return 0 if verify(arc) else 1


if __name__ == "__main__":
    sys.exit(main())
