from __future__ import annotations

import argparse
import json
from pathlib import Path
from masq_common import rebuild_him5_from_manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Pack patched Himauri .bin files back to Him5 .hxp, uncompressed.")
    ap.add_argument("patched_dir", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()

    manifest_path = args.patched_dir / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    raw_by_name: dict[str, bytes] = {}
    for e in manifest["entries"]:
        name = str(e["name"])
        bin_name = str(e.get("bin") or f"{name}.bin")
        path = args.patched_dir / bin_name
        if not path.exists():
            raise SystemExit(f"missing bin for {name}: {path}")
        raw_by_name[name] = path.read_bytes()

    out = rebuild_him5_from_manifest(manifest, raw_by_name)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(out)
    print(f"packed {len(raw_by_name)} entries -> {args.output}")


if __name__ == "__main__":
    main()
