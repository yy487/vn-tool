"""
AI6WIN MES text extractor.

Produces one translator file per .mes:

    <name>.mes.json   A JSON array of dialogue entries:
        [
            {"id": 0, "name": "",      "message": " 闇医者　彦麻呂"},
            {"id": 1, "name": "彦麻呂", "message": "次の方、どうぞ。"},
            ...
        ]

That's it. Translators open the JSON, edit `message` (and optionally `name`),
save, and pass it to mes_inject.py. The injector reloads the source .mes
every time and re-synthesizes the whole bytecode, so no separate "state
file" is needed.

Dialogue extraction rules:
  * Every STR_PRIMARY (0x0A) opcode is a dialogue entry.
  * If the text matches the pattern "〈name〉：rest", it is split into name
    and message. Otherwise name="" and the whole text goes in message.
    (Both 〈...〉: half-width and 〈...〉：full-width colons are accepted;
    AI6WIN uses full-width.)
  * PUSH_STR (0x33) and STR_SUPPLEMENT (0x0B) are NOT emitted: the former
    carries flag/variable names, the latter is used for non-dialogue helper
    strings. They stay in the .mes untouched.

Encoding:
  * The JSON file is UTF-8 (because any editor handles that).
  * Translations are CP932-encoded only at inject time. Characters outside
    CP932 surface a clear error there.

Usage:
    python mes_extract.py <plain.mes>                   # writes <plain>.mes.json
    python mes_extract.py <src_dir> -o <work_dir>       # batch
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Allow `from mes_opcodes import ...` and `from lzss_ai import ...` when run
# from either mes/ or the parent directory.
_SELF_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _SELF_DIR.parent
for _d in (_SELF_DIR, _ROOT_DIR):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

from mes_diss import disassemble, validate
from mes_opcodes import ENCODING
from lzss_ai import decompress as _lzss_decompress


# ---------------------------------------------------------------------------
# Dialogue detection

_SPEAKER_RE = re.compile(r"^〈([^〉]+)〉[：:](.*)$", re.DOTALL)

DIALOGUE_OPCODE = 0x0A  # STR_PRIMARY


def _split_speaker(text: str) -> tuple[str, str]:
    """Split a line like '〈name〉：message' into (name, message).

    If no speaker prefix is present, returns ("", text).
    """
    m = _SPEAKER_RE.match(text)
    if m:
        return m.group(1), m.group(2)
    return "", text


# ---------------------------------------------------------------------------
# LZSS auto-decompress from sibling __arc_index.json (optional)

INDEX_JSON_NAME = "__arc_index.json"
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


def _maybe_decompress(mes_path: Path) -> tuple[bytes, bool]:
    """Return (plaintext_bytes, was_compressed). LZSS auto-handled via
    __arc_index.json in the same directory, if present."""
    raw = mes_path.read_bytes()
    idx = _load_arc_index(mes_path.parent)
    entry = idx.get(mes_path.name) or idx.get(mes_path.relative_to(mes_path.parent).as_posix())
    if entry is None:
        return raw, False
    comp, uncomp = entry
    if comp == uncomp:
        return raw, False
    if len(raw) != comp:
        raise ValueError(
            f"{mes_path.name}: on-disk {len(raw)} != index compressed_size {comp}"
        )
    return _lzss_decompress(raw, uncomp), True


# ---------------------------------------------------------------------------
# Extract one file

def extract_one(
    mes_path: Path,
    *,
    out_dir: Path | None = None,
    rel_path: Path | None = None,
    verbose: bool = True,
) -> tuple[Path, int]:
    data, was_compressed = _maybe_decompress(mes_path)
    dis = disassemble(data)
    validate(dis)

    # Build dialogue list: one entry per STR_PRIMARY, in source order.
    entries: list[dict] = []
    for ins in dis["instructions"]:
        if ins["op"] != DIALOGUE_OPCODE:
            continue
        text = ins["args"][0]
        name, message = _split_speaker(text)
        entries.append({
            "id": len(entries),
            "name": name,
            "message": message,
        })

    # Output path: <out_dir>/<rel>.mes.json if out_dir given, else sibling.
    if out_dir is not None:
        rel = rel_path if rel_path is not None else Path(mes_path.name)
        out_base = out_dir / rel
        out_base.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_base = mes_path
    json_path = out_base.with_suffix(out_base.suffix + ".json")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    if verbose:
        tag = "LZSS" if was_compressed else "raw "
        print(
            f"  {mes_path.name:<30}  [{tag}]  "
            f"dialogues={len(entries):>4}"
        )
    return json_path, len(entries)


# ---------------------------------------------------------------------------
# CLI

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Extract AI6WIN MES dialogue into a translator-friendly JSON"
    )
    p.add_argument("path", help="A .mes file or a directory of them")
    p.add_argument("-o", "--out",
                   help="Output directory for .mes.json files. "
                        "Default: next to each source .mes.")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="When path is a directory, descend into subdirectories")
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args(argv)

    target = Path(args.path)
    out_dir = Path(args.out) if args.out else None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    if target.is_file():
        extract_one(
            target,
            out_dir=out_dir,
            rel_path=Path(target.name) if out_dir else None,
            verbose=not args.quiet,
        )
        return 0

    if not target.is_dir():
        p.error(f"path not found: {target}")

    pattern = "**/*.mes" if args.recursive else "*.mes"
    files = sorted(
        f for f in target.glob(pattern)
        if f.suffix == ".mes"
        and not any(s in f.suffixes for s in (".json", ".txt"))
    )
    if not files:
        p.error(f"no .mes files under {target}")

    total = 0
    for f in files:
        rel = f.relative_to(target) if out_dir else None
        _, n = extract_one(f, out_dir=out_dir, rel_path=rel, verbose=not args.quiet)
        total += n
    if not args.quiet:
        print(f"\ndone: {len(files)} files, {total} dialogues")
    return 0


if __name__ == "__main__":
    sys.exit(main())
