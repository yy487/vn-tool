"""
AI6WIN MES text injector.

Reverses mes_extract.py:

    source .mes + <n>.mes.json  =>  translated .mes

Every run re-disassembles the source .mes from scratch, walks its STR_PRIMARY
opcodes in the same order the extractor did, and replaces each one's text
with the corresponding JSON entry. The JSON holds (name, message) pairs; we
reconstruct "〈name〉：message" if name is non-empty, otherwise just write
message. Order-based matching by `id` keeps the scheme brittle-proof: the
JSON's id == the Nth STR_PRIMARY in source order.

Source .mes handling:
  * LZSS-compressed source files are auto-decompressed in memory using the
    sibling __arc_index.json (same as the extractor).
  * The injector always writes PLAINTEXT bytes to the output. arc_pack later
    notices "on-disk size != comp_size from manifest" and marks the entry
    as uncompressed (comp_size := uncomp_size := new length), so the engine
    skips its LZSS path. We never try to re-compress.

CP932 enforcement:
  * Translations are encoded as CP932 at assemble time.
  * All failures are collected and reported in one batch with id, position,
    character, and codepoint, so translators can fix everything at once.

Usage:
    # three-directory setup (src read-only, work = jsons, out = new mes tree)
    python mes_inject.py <src_dir> -w <work_dir> -o <out_dir>

    # single file
    python mes_inject.py <src.mes> -w <dir_with_json> -o <out.mes>

    # or the JSON in the same dir as the source (default)
    python mes_inject.py <src.mes> -o <out.mes>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SELF_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _SELF_DIR.parent
for _d in (_SELF_DIR, _ROOT_DIR):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

from mes_asm import assemble
from mes_diss import disassemble, validate
from mes_opcodes import ENCODING
from lzss_ai import decompress as _lzss_decompress


DIALOGUE_OPCODE = 0x0A  # STR_PRIMARY
INDEX_JSON_NAME = "__arc_index.json"


# ---------------------------------------------------------------------------
# LZSS auto-decompress (shared logic with mes_extract; kept inline so inject
# can run independently of the extractor module).

_INDEX_CACHE: dict[Path, dict[str, tuple[int, int]]] = {}


def _load_arc_index(dir_path: Path) -> dict[str, tuple[int, int]]:
    if dir_path in _INDEX_CACHE:
        return _INDEX_CACHE[dir_path]
    path = dir_path / INDEX_JSON_NAME
    if not path.is_file():
        _INDEX_CACHE[dir_path] = {}
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        _INDEX_CACHE[dir_path] = {}
        return {}
    out = {
        e["filename"]: (int(e["compressed_size"]), int(e["uncompressed_size"]))
        for e in raw
    }
    _INDEX_CACHE[dir_path] = out
    return out


def _maybe_decompress(mes_path: Path) -> bytes:
    raw = mes_path.read_bytes()
    idx = _load_arc_index(mes_path.parent)
    entry = idx.get(mes_path.name)
    if entry is None:
        return raw
    comp, uncomp = entry
    if comp == uncomp or len(raw) != comp:
        return raw
    return _lzss_decompress(raw, uncomp)


# ---------------------------------------------------------------------------
# Reassembly

def _entry_to_text(entry: dict) -> str:
    """Reconstruct the STR_PRIMARY text from a JSON entry.

    Rule mirrors the extractor's split: non-empty name means the text was
    "〈name〉：message"; empty name means message stood alone.
    """
    name = entry.get("name", "")
    msg = entry.get("message", "")
    if name:
        return f"〈{name}〉：{msg}"
    return msg


def _validate_cp932(entries: list[dict]) -> None:
    """Collect every translation that won't encode in CP932 and raise once."""
    fails: list[str] = []
    for ent in entries:
        text = _entry_to_text(ent)
        try:
            text.encode(ENCODING)
        except UnicodeEncodeError as e:
            ch = text[e.start]
            fails.append(
                f"  id {ent.get('id')}: character {ch!r} (U+{ord(ch):04X}) "
                f"at position {e.start} cannot be encoded in {ENCODING.upper()}\n"
                f"       name={ent.get('name','')!r}  "
                f"message={ent.get('message','')!r}"
            )
    if fails:
        raise ValueError(
            f"{len(fails)} translation(s) contain characters not representable "
            f"in {ENCODING.upper()}:\n" + "\n".join(fails)
            + f"\n\nNote: simplified-Chinese hanzi are mostly outside CP932. "
              f"Use Japanese or CP932/JIS-range kanji (traditional forms are fine)."
        )


def _lzss_fake_compress(src: bytes) -> bytes:
    """Emit a valid AI-series LZSS stream that decodes back to `src` padded
    to a multiple of 8 bytes (padding is NUL).

    Every 8-byte chunk is encoded as [0xFF, b0..b7]: the control flag 0xFF
    means "all 8 tokens are literals", so the engine's decompressor (ring
    buffer fill=0, init pos=0xFEE, LSB-first flags, flag=1 → literal) reads
    each byte straight into the output. No back-references are emitted, so
    we don't have to worry about ring-buffer state or match correctness —
    the stream is always valid by construction.

    Callers must set the archive entry's uncompressed_size to the PADDED
    length (i.e. len(src) rounded up to 8), and compressed_size to
    len(result). The engine's interpreter treats trailing NULs as YIELD
    opcodes, which is inert after the script's natural RETURN/JUMP flow.
    """
    buf = bytearray(src)
    rem = len(buf) % 8
    if rem:
        buf.extend(b"\x00" * (8 - rem))
    out = bytearray()
    for i in range(0, len(buf), 8):
        out.append(0xFF)
        out.extend(buf[i : i + 8])
    return bytes(out)


def inject_one(
    mes_path: Path,
    json_path: Path,
    out_path: Path,
    *,
    verbose: bool = True,
) -> Path:
    if not json_path.is_file():
        raise FileNotFoundError(f"missing dialogue JSON: {json_path}")
    entries = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError(f"{json_path}: expected a JSON array, got {type(entries).__name__}")

    _validate_cp932(entries)

    data = _maybe_decompress(mes_path)
    dis = disassemble(data)
    validate(dis)

    # Count source dialogues for sanity.
    src_count = sum(1 for i in dis["instructions"] if i["op"] == DIALOGUE_OPCODE)
    if len(entries) != src_count:
        raise ValueError(
            f"{mes_path.name}: JSON has {len(entries)} entries but "
            f"source has {src_count} STR_PRIMARY opcodes"
        )

    # Walk STR_PRIMARY in order and apply translations by positional id.
    idx = 0
    applied = 0
    for ins in dis["instructions"]:
        if ins["op"] != DIALOGUE_OPCODE:
            continue
        ent = entries[idx]
        new_text = _entry_to_text(ent)
        if new_text != ins["args"][0]:
            ins["args"][0] = new_text
            applied += 1
        idx += 1

    plain = assemble(dis)
    # Wrap the assembled plaintext in a fake-LZSS stream so the engine stays
    # on its normal Size != UnpackedSize decompression path.
    compressed = _lzss_fake_compress(plain)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(compressed)

    # Remember the new uncompressed_size (padded) and compressed_size so the
    # caller / arc_pack can patch __arc_index.json correctly.
    padded_len = len(plain) + ((-len(plain)) % 8)

    if verbose:
        print(
            f"  {mes_path.name:<30}  "
            f"dialogues={src_count:>4}  changed={applied:>4}  "
            f"plain={len(plain)}B  padded={padded_len}B  comp={len(compressed)}B"
        )
    # Return both lengths so the batch driver can update the manifest.
    return out_path, padded_len, len(compressed)


# ---------------------------------------------------------------------------
# CLI helpers

def _json_for(mes_path: Path, work_dir: Path | None, rel: Path | None) -> Path:
    """Locate the translator JSON for a given source .mes."""
    if work_dir is None:
        return mes_path.with_suffix(mes_path.suffix + ".json")
    base = work_dir / (rel if rel is not None else Path(mes_path.name))
    return base.with_suffix(base.suffix + ".json")


def _mirror_aux_files(
    target: Path,
    out_dir: Path,
    size_updates: dict[str, tuple[int, int]],
    quiet: bool,
) -> None:
    """Copy __arc_index.json (with size updates applied) and every non-.mes
    manifest entry into out_dir, so arc_pack can consume it directly.

    size_updates maps filename -> (new_compressed_size, new_uncompressed_size)
    for files we just rewrote. Entries we didn't touch are copied verbatim.
    """
    src_idx = target / INDEX_JSON_NAME
    if not src_idx.is_file():
        return
    try:
        manifest = json.loads(src_idx.read_text(encoding="utf-8"))
    except Exception:
        manifest = []

    aux = 0
    for item in manifest:
        name = item["filename"]
        name_fs = name.replace("\\", "/")
        # Update sizes for rewritten files so arc_pack emits a consistent header.
        if name in size_updates:
            new_comp, new_uncomp = size_updates[name]
            item["compressed_size"] = new_comp
            item["uncompressed_size"] = new_uncomp
        dst = out_dir / name_fs
        if dst.exists():
            # .mes we just wrote — leave it.
            continue
        src = target / name_fs
        if not src.is_file():
            if not quiet:
                print(f"  [warn] missing in source: {src}")
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        aux += 1

    (out_dir / INDEX_JSON_NAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if not quiet:
        print(
            f"copied {INDEX_JSON_NAME} (with {len(size_updates)} size updates) "
            f"+ {aux} aux file(s) -> {out_dir}"
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Inject translations into AI6WIN .mes"
    )
    p.add_argument("path", help="A .mes file or a source directory")
    p.add_argument("-o", "--out",
                   help="Output file (single mode) or directory (batch mode). "
                        "Batch -o auto-mirrors __arc_index.json and non-.mes "
                        "manifest entries so arc_pack can consume the dir.")
    p.add_argument("-w", "--work-dir",
                   help="Directory holding the .mes.json files from mes_extract. "
                        "Default: next to each source .mes.")
    p.add_argument("-r", "--recursive", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args(argv)

    target = Path(args.path)
    work_dir = Path(args.work_dir) if args.work_dir else None

    # Single-file mode
    if target.is_file():
        out = Path(args.out) if args.out else target.with_suffix(target.suffix + ".new")
        jsn = _json_for(target, work_dir, Path(target.name) if work_dir else None)
        inject_one(target, jsn, out, verbose=not args.quiet)
        return 0

    if not target.is_dir():
        p.error(f"path not found: {target}")

    # Batch mode
    if not args.out:
        p.error("batch mode requires -o <out_dir>")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    pattern = "**/*.mes" if args.recursive else "*.mes"
    files = sorted(
        f for f in target.glob(pattern)
        if f.suffix == ".mes"
        and not any(s in f.suffixes for s in (".json", ".txt", ".new"))
    )
    if not files:
        p.error(f"no .mes files under {target}")

    size_updates: dict[str, tuple[int, int]] = {}
    for f in files:
        rel = f.relative_to(target)
        jsn = _json_for(f, work_dir, rel if work_dir else None)
        dst = out_dir / rel
        _, new_uncomp, new_comp = inject_one(f, jsn, dst, verbose=not args.quiet)
        # Manifest keys use archive-relative paths with forward slashes.
        manifest_key = str(rel).replace("\\", "/")
        size_updates[manifest_key] = (new_comp, new_uncomp)

    _mirror_aux_files(target, out_dir, size_updates, quiet=args.quiet)

    if not args.quiet:
        print(f"\ndone: {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
