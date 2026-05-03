from __future__ import annotations

import argparse
import bisect
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from masq_common import (
    compose_name_message,
    load_text_jsons,
    read_u24be,
    write_u24be,
    scan_cp932_strings,
)


@dataclass(frozen=True)
class Replacement:
    start: int
    end: int
    text: str
    encoded: bytes
    source: dict[str, Any]


class OffsetMap:
    def __init__(self, replacements: list[Replacement]):
        self.repls = sorted(replacements, key=lambda r: r.start)
        self.starts = [r.start for r in self.repls]
        self.ends = [r.end for r in self.repls]
        self.prefix_deltas: list[int] = []
        delta = 0
        for r in self.repls:
            self.prefix_deltas.append(delta)
            delta += len(r.encoded) - (r.end - r.start)
        self.total_delta = delta

    def is_inside_replacement(self, pos: int, width: int = 1) -> bool:
        idx = bisect.bisect_right(self.starts, pos) - 1
        if idx >= 0 and pos < self.ends[idx]:
            return True
        idx = bisect.bisect_right(self.starts, pos + width - 1) - 1
        return idx >= 0 and pos + width - 1 < self.ends[idx]

    def map_pos(self, pos: int) -> int:
        idx = bisect.bisect_right(self.starts, pos) - 1
        if idx >= 0:
            r = self.repls[idx]
            base_delta = self.prefix_deltas[idx]
            if pos < r.end:
                return r.start + base_delta
            return pos + base_delta + (len(r.encoded) - (r.end - r.start))
        return pos


def find_script_start(data: bytes) -> int:
    if not data.startswith(b"Himauri\0"):
        return 0
    if len(data) <= 0x10:
        return len(data)
    if data[0x0B] == 0:
        return 0x10
    p = 0x10
    while p < len(data) and data[p] != 0:
        p += 1
    return min(p + 1, len(data))


def collect_string_ranges(data: bytes, encoding: str) -> list[tuple[int, int]]:
    return [(s, e) for s, e, _ in scan_cp932_strings(data, min_chars=1, encoding=encoding)]


def in_ranges(pos: int, width: int, ranges: list[tuple[int, int]]) -> bool:
    end = pos + width
    starts = [r[0] for r in ranges]
    i = bisect.bisect_right(starts, pos) - 1
    if i >= 0 and ranges[i][1] > pos:
        return True
    j = bisect.bisect_right(starts, end - 1) - 1
    return j >= 0 and ranges[j][1] > end - 1


def expr_len(data: bytes, pos: int) -> int:
    """Length of a FUN_00401c60 numeric expression, including trailing FF."""
    p = pos
    n = len(data)
    while p < n:
        b = data[p]
        p += 1
        if b == 0xFF:
            return p - pos
        hi = b & 0xF0
        lo = b & 0x0F
        if b < 0x40:
            if hi == 0:
                if lo == 0x0D:
                    p += 1
                elif lo == 0x0E:
                    p += 2
                elif lo == 0x0F:
                    p += 4
            else:
                if lo == 0x0E:
                    p += 1
                elif lo == 0x0F:
                    p += 2
        if p > n:
            raise ValueError(f"expression overruns script at {pos:#x}")
    raise ValueError(f"unterminated expression at {pos:#x}")


def string_len(data: bytes, pos: int) -> int:
    """Length consumed by FUN_004021f0 at pos."""
    n = len(data)
    if pos >= n:
        raise ValueError(f"string read past EOF at {pos:#x}")
    b = data[pos]
    if b < 0x20:
        if b == 0:
            return 1
        if b < 6:
            return 2
        if b < 0x0C:
            return 3
        return 1 + expr_len(data, pos + 1)
    z = data.find(b"\0", pos)
    if z < 0:
        raise ValueError(f"unterminated string at {pos:#x}")
    return z + 1 - pos


def argpack_len(data: bytes, pos: int) -> int:
    """Length consumed by FUN_00404880 argument pack, including final 00."""
    p = pos
    n = len(data)
    while p < n:
        typ = data[p]
        p += 1
        if typ == 0:
            return p - pos
        if typ == 1:
            p += string_len(data, p)
        else:
            p += expr_len(data, p)
    raise ValueError(f"unterminated argpack at {pos:#x}")


# Only the first-level interpreter opcodes that contain real script PC targets.
# This table is derived directly from EXE switchD_00404878:
#   1/3: conditional jump with one u24
#   2: two-way conditional jump with two u24s
#   4: unconditional jump with one u24
#   5: switch table of u24s
#   6: call-like opcode: argpack + u24 target
#   0x5e: engine helper that receives a u24 target-like value
CONTROL_OPS = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x5E}


def skip_opcode_operands(data: bytes, pos: int, opcode: int) -> int:
    """Return position after operands for known non-control opcode."""
    p = pos
    # Control opcodes are handled by find_control_target_fields.
    if opcode in CONTROL_OPS:
        raise ValueError("control opcode should be handled separately")
    # Most engine command opcodes are simple sequences of numeric expressions and strings.
    # The arities below are copied from the decompiled interpreter call order.
    specs: dict[int, str] = {
        0x00: "E", 0x07: "E", 0x08: "E",
        0x09: "SEEA", 0x0A: "EA", 0x0B: "ES", 0x0C: "ES",
        0x0D: "SS", 0x0E: "S", 0x0F: "ESEE", 0x10: "ES",
        0x11: "SEEE", 0x12: "ES", 0x13: "SE", 0x14: "E",
        0x16: "E", 0x19: "E", 0x1D: "EEE", 0x1E: "E",
        0x1F: "SEEEEE", 0x22: "EE", 0x23: "E", 0x24: "EE",
        0x25: "ESEE", 0x26: "E", 0x29: "EEEEE", 0x2B: "EE",
        0x2C: "EEE", 0x2D: "EEE", 0x2E: "EE", 0x2F: "EE",
        0x31: "ESEEEEE", 0x32: "EEEE", 0x33: "EEEEEEEE",
        0x34: "EE", 0x35: "EEE", 0x36: "ESESE", 0x37: "E",
        0x38: "EEEEEEEEE", 0x3B: "S", 0x3C: "S", 0x3D: "EE",
        0x3E: "S", 0x3F: "EE", 0x41: "EEEEEEEE", 0x42: "EESEEEE",
        0x43: "EEEEEEEEEEEE", 0x44: "E", 0x48: "SS", 0x49: "S",
        0x4A: "SS", 0x4B: "ES", 0x4C: "E", 0x4D: "E",
        0x4E: "EE", 0x4F: "EE", 0x50: "EEE", 0x51: "EE",
        0x52: "E", 0x53: "E", 0x54: "EE", 0x57: "ES",
        0x58: "ESE", 0x59: "ES", 0x5A: "EEE", 0x5B: "SSS",
        0x5C: "EEEEEE", 0x5F: "E", 0x60: "EE", 0x62: "EEE",
        0x64: "SE", 0x65: "EE", 0x69: "EES", 0x6A: "EEE",
        0x6D: "S", 0x6E: "E", 0x6F: "EEE", 0x70: "EEE",
    }
    # Known no-operand opcodes / fallthrough cases in the interpreter.
    if opcode in {0x15, 0x17, 0x18, 0x1A, 0x1B, 0x1C, 0x20, 0x21, 0x27, 0x28, 0x2A, 0x30, 0x3A, 0x40, 0x45, 0x46, 0x47, 0x55, 0x56, 0x5D, 0x63, 0x66, 0x67, 0x68, 0x6B, 0x6C, 0x71}:
        return p
    if opcode == 0x39:
        if p >= len(data):
            raise ValueError(f"truncated opcode 39 at {pos-1:#x}")
        count = data[p]
        p += 1
        p += expr_len(data, p)
        p += expr_len(data, p)
        for _ in range(count):
            p += string_len(data, p)
            p += expr_len(data, p)
            p += expr_len(data, p)
        return p
    if opcode == 0x61:
        p += expr_len(data, p)
        if p >= len(data):
            raise ValueError(f"truncated opcode 61 at {pos-1:#x}")
        typ = data[p]
        p += 1
        if typ == 0:
            p += expr_len(data, p)
        else:
            p += string_len(data, p)
        return p
    spec = specs.get(opcode)
    if spec is None:
        raise ValueError(f"unknown opcode {opcode:#x} at {pos-1:#x}")
    for ch in spec:
        if ch == "E":
            p += expr_len(data, p)
        elif ch == "S":
            p += string_len(data, p)
        elif ch == "A":
            p += argpack_len(data, p)
        else:
            raise AssertionError(ch)
    return p


def find_control_target_fields(data: bytes, stream_start: int) -> list[tuple[int, int, str]]:
    """Find script PC target fields by parsing bytecode instruction boundaries.

    v4 still treated every byte value 04 as a possible direct jump. That is unsafe:
    byte 04 also appears inside numeric expressions / command arguments.  This v5
    version follows the interpreter's operand grammar, so only opcode-boundary
    04/05/etc. fields are relocated.
    """
    fields: list[tuple[int, int, str]] = []
    p = stream_start
    n = len(data)
    while p < n:
        op_pos = p
        opcode = data[p]
        p += 1
        try:
            if opcode == 0x01:
                p += expr_len(data, p)
                fields.append((p, read_u24be(data, p), "jump01")); p += 3
            elif opcode == 0x02:
                p += expr_len(data, p)
                fields.append((p, read_u24be(data, p), "jump02_true")); p += 3
                fields.append((p, read_u24be(data, p), "jump02_false")); p += 3
            elif opcode == 0x03:
                p += expr_len(data, p)
                fields.append((p, read_u24be(data, p), "jump03")); p += 3
            elif opcode == 0x04:
                fields.append((p, read_u24be(data, p), "jump04")); p += 3
            elif opcode == 0x05:
                p += expr_len(data, p)
                count = int.from_bytes(data[p:p+2], "big"); p += 2
                if not (0 <= count <= 0x400):
                    raise ValueError(f"bad switch count {count} at {op_pos:#x}")
                for k in range(count):
                    fields.append((p, read_u24be(data, p), "switch05")); p += 3
            elif opcode == 0x06:
                p += argpack_len(data, p)
                fields.append((p, read_u24be(data, p), "call06")); p += 3
            elif opcode == 0x5E:
                p += expr_len(data, p)
                fields.append((p, read_u24be(data, p), "target5e")); p += 3
            else:
                p = skip_opcode_operands(data, p, opcode)
        except Exception:
            # If a rare opcode form is still missing, stop structured parsing instead of
            # risking false relocation.  Already collected earlier fields remain valid.
            break
    # Keep only fields whose targets look like real script offsets.
    return [(pos, target, kind) for pos, target, kind in fields if stream_start <= target < n]

def find_generic_u24_target_fields(data: bytes, stream_start: int, string_ranges: list[tuple[int, int]]) -> list[tuple[int, int, str]]:
    fields: list[tuple[int, int, str]] = []
    n = len(data)
    opcode_like = set(range(0x01, 0x72)) | {0x80, 0x81}
    for p in range(stream_start, n - 2):
        if in_ranges(p, 3, string_ranges):
            continue
        value = read_u24be(data, p)
        if stream_start <= value < n and data[value] in opcode_like:
            if value < 0x100 and p + 3 < n and data[p + 3] == 0xFF:
                continue
            fields.append((p, value, "u24"))
    return fields


def item_replacement_text(item: dict[str, Any]) -> str:
    name = item.get("name")
    msg = item.get("msg")
    if not isinstance(name, str):
        name = ""
    if not isinstance(msg, str):
        msg = ""
    kind = str(item.get("_kind", ""))
    if kind == "message":
        sep = item.get("_sep")
        if not isinstance(sep, str):
            sep = "\n"
        return compose_name_message(name, msg, sep)
    # For choice/literal, name is normally empty.  If user intentionally set a name,
    # still compose message style to avoid silently dropping it.
    sep = item.get("_sep")
    if not isinstance(sep, str):
        sep = "\n"
    return compose_name_message(name, msg, sep) if name else msg


def build_replacements(items: list[dict[str, Any]], data: bytes, encoding: str, errors: str) -> list[Replacement]:
    repls: list[Replacement] = []
    for item in items:
        start = int(item["_offset"])
        end = int(item.get("_end") or 0)
        if end <= start:
            z = data.find(b"\0", start)
            if z < 0:
                raise ValueError(f"missing NUL terminator for {item.get('_json_path') or item}")
            end = z + 1
        text = item_replacement_text(item)
        encoded = text.encode(encoding, errors=errors) + b"\0"
        old = data[start : end - 1]
        try:
            old_text = old.decode(encoding)
        except Exception:
            old_text = None
        if old_text == text:
            continue
        repls.append(Replacement(start, end, text, encoded, item))
    repls.sort(key=lambda r: r.start)
    last_end = -1
    for r in repls:
        if r.start < last_end:
            raise ValueError(f"overlapping replacements around {r.start:#x}; duplicated text json? {r.source.get('_json_path')}")
        if not (0 <= r.start < r.end <= len(data)):
            raise ValueError(f"replacement range out of bounds: {r}")
        last_end = r.end
    return repls


def apply_replacements(data: bytes, repls: list[Replacement]) -> bytes:
    if not repls:
        return data
    out = bytearray()
    p = 0
    for r in repls:
        out += data[p : r.start]
        out += r.encoded
        p = r.end
    out += data[p:]
    return bytes(out)


def relocate_script(old_data: bytes, new_data: bytes, repls: list[Replacement], *, encoding: str, generic_u24: bool) -> tuple[bytes, list[dict[str, Any]]]:
    if not repls:
        return new_data, []
    mapper = OffsetMap(repls)
    stream_start = find_script_start(old_data)
    string_ranges = collect_string_ranges(old_data, encoding)
    fields = find_control_target_fields(old_data, stream_start)
    if generic_u24:
        fields += find_generic_u24_target_fields(old_data, stream_start, string_ranges)

    chosen: dict[int, tuple[int, str]] = {}
    for pos, target, kind in fields:
        if pos not in chosen or chosen[pos][1] != "switch":
            chosen[pos] = (target, kind)

    out = bytearray(new_data)
    patched: list[dict[str, Any]] = []
    for old_field_pos, (old_target, kind) in sorted(chosen.items()):
        if mapper.is_inside_replacement(old_field_pos, 3):
            continue
        new_field_pos = mapper.map_pos(old_field_pos)
        new_target = mapper.map_pos(old_target)
        if old_target == new_target:
            continue
        if new_field_pos + 3 > len(out):
            raise ValueError(f"relocated field out of range: {old_field_pos:#x}->{new_field_pos:#x}")
        current = read_u24be(out, new_field_pos)
        if current != old_target:
            if kind == "switch":
                raise ValueError(
                    f"relocation guard failed at {old_field_pos:#x}->{new_field_pos:#x}: "
                    f"expected {old_target:#x}, got {current:#x}"
                )
            continue
        write_u24be(out, new_field_pos, new_target)
        patched.append(
            {
                "kind": kind,
                "old_field_offset": old_field_pos,
                "new_field_offset": new_field_pos,
                "old_target": old_target,
                "new_target": new_target,
            }
        )
    if out.startswith(b"Himauri\0"):
        write_u24be(out, 8, len(out))
    return bytes(out), patched


def copy_unpacked(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for p in src.iterdir():
        if p.is_file():
            shutil.copy2(p, dst / p.name)


def main() -> None:
    ap = argparse.ArgumentParser(description="Inject edited per-text JSONs into unpacked Masq Himauri .bin files.")
    ap.add_argument("unpacked_dir", type=Path)
    ap.add_argument("texts_dir", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True, help="patched unpacked directory")
    ap.add_argument("--encoding", default="cp932")
    ap.add_argument("--errors", default="strict", choices=["strict", "replace", "ignore"])
    ap.add_argument("--generic-u24", action="store_true", help="also scan and relocate generic u24-looking script targets; off by default")
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()

    if not args.unpacked_dir.is_dir():
        raise SystemExit(f"not a directory: {args.unpacked_dir}")
    items = load_text_jsons(args.texts_dir)
    by_file: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        by_file.setdefault(str(item["_file"]), []).append(item)

    if args.output.exists():
        shutil.rmtree(args.output)
    copy_unpacked(args.unpacked_dir, args.output)

    report: dict[str, Any] = {
        "unpacked": str(args.unpacked_dir),
        "texts": str(args.texts_dir),
        "output": str(args.output),
        "files_changed": 0,
        "replacement_count": 0,
        "relocation_count": 0,
        "files": [],
    }

    for file_name, file_items in sorted(by_file.items()):
        bin_path = args.unpacked_dir / f"{file_name}.bin"
        if not bin_path.exists():
            raise SystemExit(f"missing source bin: {bin_path}")
        old_data = bin_path.read_bytes()
        repls = build_replacements(file_items, old_data, args.encoding, args.errors)
        if not repls:
            continue
        replaced = apply_replacements(old_data, repls)
        relocated, patches = relocate_script(
            old_data,
            replaced,
            repls,
            encoding=args.encoding,
            generic_u24=args.generic_u24,
        )
        (args.output / f"{file_name}.bin").write_bytes(relocated)
        report["files_changed"] += 1
        report["replacement_count"] += len(repls)
        report["relocation_count"] += len(patches)
        report["files"].append(
            {
                "file": file_name,
                "old_size": len(old_data),
                "new_size": len(relocated),
                "delta": len(relocated) - len(old_data),
                "replacements": len(repls),
                "relocations": patches,
            }
        )

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"patched -> {args.output}; files_changed={report['files_changed']} "
        f"replacements={report['replacement_count']} relocations={report['relocation_count']}"
    )


if __name__ == "__main__":
    main()
