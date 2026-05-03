from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.check_call(cmd)


def main() -> None:
    ap = argparse.ArgumentParser(description="One-shot Masq workflow: hxp + edited text-json dir -> new hxp.")
    ap.add_argument("input_hxp", type=Path)
    ap.add_argument("texts_dir", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--workdir", type=Path, default=Path("_masq_build"))
    ap.add_argument("--encoding", default="cp932")
    ap.add_argument("--generic-u24", action="store_true")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    unpacked = args.workdir / "unpacked"
    patched = args.workdir / "patched"
    report = args.workdir / "inject_report.json"
    args.workdir.mkdir(parents=True, exist_ok=True)

    run([sys.executable, str(here / "masq_unpack.py"), str(args.input_hxp), "-o", str(unpacked)])
    inject_cmd = [
        sys.executable,
        str(here / "masq_inject.py"),
        str(unpacked),
        str(args.texts_dir),
        "-o",
        str(patched),
        "--encoding",
        args.encoding,
        "--report",
        str(report),
    ]
    if args.generic_u24:
        inject_cmd.append("--generic-u24")
    run(inject_cmd)
    run([sys.executable, str(here / "masq_pack.py"), str(patched), "-o", str(args.output)])


if __name__ == "__main__":
    main()
