from __future__ import annotations

import argparse
import json
from pathlib import Path
from masq_common import parse_him5, archive_to_manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Unpack Masq_scn.hxp Him5 archive to raw Himauri .bin files.")
    ap.add_argument("input_hxp", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()

    arc = parse_him5(args.input_hxp)
    args.output.mkdir(parents=True, exist_ok=True)
    for e in arc.entries:
        (args.output / f"{e.name}.bin").write_bytes(e.raw)
    manifest = archive_to_manifest(arc, source=str(args.input_hxp))
    (args.output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"unpacked {len(arc.entries)} entries -> {args.output}")


if __name__ == "__main__":
    main()
