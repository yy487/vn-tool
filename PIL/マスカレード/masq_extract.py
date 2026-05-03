from __future__ import annotations

import argparse
import json
from pathlib import Path
from masq_common import scan_cp932_strings, looks_visible_text, split_name_message_ex, classify_context


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract visible texts from unpacked Masq Himauri .bin files into one JSON per script.")
    ap.add_argument("unpacked_dir", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True, help="output text-json directory")
    ap.add_argument("--encoding", default="cp932")
    ap.add_argument("--min-chars", type=int, default=1)
    args = ap.parse_args()

    if not args.unpacked_dir.is_dir():
        raise SystemExit(f"not a directory: {args.unpacked_dir}")
    args.output.mkdir(parents=True, exist_ok=True)

    file_count = 0
    text_count = 0
    for bin_path in sorted(args.unpacked_dir.glob("*.bin")):
        file_name = bin_path.stem
        data = bin_path.read_bytes()
        entries = []
        local_index = 0
        for start, end, raw_text in scan_cp932_strings(data, min_chars=args.min_chars, encoding=args.encoding):
            if not looks_visible_text(raw_text):
                continue
            kind = classify_context(data, start)
            # Keep text-like contexts. Other cmd_xx entries are often resources/labels.
            if kind not in ("message", "choice", "literal") and not raw_text.startswith("【"):
                continue
            name, msg, sep = split_name_message_ex(raw_text)
            entries.append({
                "name": name,
                "msg": msg,
                "_offset": start,
                "_end": end,
                "_kind": kind,
                "_sep": sep,
                "_index": local_index,
            })
            local_index += 1
        if entries:
            obj = {"_file": file_name, "texts": entries}
            (args.output / f"{file_name}.json").write_text(
                json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            file_count += 1
            text_count += len(entries)
    print(f"extracted {text_count} texts in {file_count} script json files -> {args.output}")


if __name__ == "__main__":
    main()
