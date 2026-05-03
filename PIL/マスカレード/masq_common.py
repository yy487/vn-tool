from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

JP_RE = re.compile(r"[\u3040-\u30ff\u3400-\u9fff]")
ASCII_RESOURCE_RE = re.compile(r"^[A-Za-z0-9_./\\:-]+$")
RESOURCE_RE = re.compile(
    r"^(?:bg|ev|f|biki|se|bgm|voice|tachi|sys|system|eff|ef|m|sd|sp|cg|cut|mask|movie)[A-Za-z0-9_./\\:-]*$",
    re.I,
)


def read_u24be(data: bytes | bytearray, off: int) -> int:
    return (data[off] << 16) | (data[off + 1] << 8) | data[off + 2]


def write_u24be(buf: bytearray, off: int, value: int) -> None:
    if not (0 <= value <= 0xFFFFFF):
        raise ValueError(f"u24 overflow: {value:#x}")
    buf[off : off + 3] = bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


@dataclass
class HxpEntry:
    name: str
    offset: int
    bucket_index: int
    bucket_order: int
    compressed_flag: int
    unpacked_size: int
    payload_size: int
    raw: bytes


@dataclass
class HxpArchive:
    bucket_count: int
    buckets: list[dict[str, int]]
    entries: list[HxpEntry]


def decompress_him(data: bytes, expected: int) -> bytes:
    p = 0
    out = bytearray()
    n = len(data)
    while len(out) < expected and p < n:
        b = data[p]
        p += 1
        if b < 0x20:
            if b < 0x1D:
                cnt = b + 1
            elif b == 0x1D:
                if p >= n:
                    raise ValueError("truncated literal length-1")
                cnt = data[p] + 0x1E
                p += 1
            elif b == 0x1E:
                if p + 2 > n:
                    raise ValueError("truncated literal length-2")
                cnt = ((data[p] << 8) | data[p + 1]) + 0x11E
                p += 2
            else:
                if p + 4 > n:
                    raise ValueError("truncated literal length-4")
                cnt = (data[p] << 24) | (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3]
                p += 4
            if p + cnt > n:
                raise ValueError(f"truncated literal: need {cnt} at {p}/{n}")
            out += data[p : p + cnt]
            p += cnt
            continue

        if b & 0x80:
            if p >= n:
                raise ValueError("truncated backref A")
            dist = ((b & 0x1F) << 8) | data[p]
            p += 1
            length = ((b >> 5) & 3) + 3
        elif (b & 0x60) == 0x20:
            dist = (b >> 2) & 7
            length = (b & 3) + 3
        elif (b & 0x60) == 0x40:
            if p >= n:
                raise ValueError("truncated backref B")
            dist = data[p]
            p += 1
            length = (b & 0x1F) + 7
        else:
            if p + 2 > n:
                raise ValueError("truncated backref C")
            dist = ((b & 0x1F) << 8) | data[p]
            p += 1
            lb = data[p]
            p += 1
            if lb == 0xFE:
                if p + 2 > n:
                    raise ValueError("truncated backref C/FE")
                length = ((data[p] << 8) | data[p + 1]) + 0x105
                p += 2
            elif lb == 0xFF:
                if p + 4 > n:
                    raise ValueError("truncated backref C/FF")
                length = (data[p] << 24) | (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3]
                length += 3
                p += 4
            else:
                length = lb + 7
        distance = dist + 1
        if distance <= 0 or distance > len(out):
            raise ValueError(f"bad distance {distance}, out={len(out)}, p={p}")
        for _ in range(length):
            out.append(out[-distance])
            if len(out) >= expected:
                break
    if len(out) != expected:
        raise ValueError(f"decompressed {len(out)} != expected {expected}, p={p}/{n}")
    return bytes(out)


def parse_him5(path: Path) -> HxpArchive:
    blob = path.read_bytes()
    if blob[:4] != b"Him5":
        raise ValueError(f"not Him5: {path}")
    bucket_count = struct.unpack_from("<I", blob, 4)[0]
    buckets: list[dict[str, int]] = []
    found: list[dict[str, Any]] = []
    for bi in range(bucket_count):
        size, off = struct.unpack_from("<II", blob, 8 + bi * 8)
        buckets.append({"bucket_index": bi, "size": size, "offset": off})
        p = off
        end = off + size
        order = 0
        while p < end:
            rec_len = blob[p]
            if rec_len == 0:
                p += 1
                break
            entry_off = int.from_bytes(blob[p + 1 : p + 5], "big")
            raw_name = blob[p + 5 : p + rec_len].split(b"\0", 1)[0]
            name = raw_name.decode("ascii", "replace")
            found.append({"name": name, "offset": entry_off, "bucket_index": bi, "bucket_order": order})
            p += rec_len
            order += 1
    found_sorted = sorted(found, key=lambda x: x["offset"])
    entries: list[HxpEntry] = []
    for idx, item in enumerate(found_sorted):
        start = item["offset"]
        end = found_sorted[idx + 1]["offset"] if idx + 1 < len(found_sorted) else len(blob)
        compressed_flag, usize = struct.unpack_from("<II", blob, start)
        payload = blob[start + 8 : end]
        if compressed_flag == 0 or len(payload) == usize:
            raw = bytes(payload)
        else:
            raw = decompress_him(bytes(payload), usize)
        entries.append(
            HxpEntry(
                name=item["name"],
                offset=start,
                bucket_index=item["bucket_index"],
                bucket_order=item["bucket_order"],
                compressed_flag=compressed_flag,
                unpacked_size=usize,
                payload_size=len(payload),
                raw=raw,
            )
        )
    return HxpArchive(bucket_count=bucket_count, buckets=buckets, entries=entries)


def archive_to_manifest(archive: HxpArchive, source: str = "") -> dict[str, Any]:
    return {
        "format": "Him5/Masq/Himauri",
        "source": source,
        "bucket_count": archive.bucket_count,
        "entries": [
            {
                "name": e.name,
                "bucket_index": e.bucket_index,
                "bucket_order": e.bucket_order,
                "original_offset": e.offset,
                "compressed_flag": e.compressed_flag,
                "unpacked_size": len(e.raw),
                "payload_size": e.payload_size,
                "bin": f"{e.name}.bin",
            }
            for e in archive.entries
        ],
    }


def rebuild_him5_from_manifest(manifest: dict[str, Any], raw_by_name: dict[str, bytes]) -> bytes:
    bucket_count = int(manifest["bucket_count"])
    entries_meta = list(manifest["entries"])

    bucket_records: dict[int, list[dict[str, Any]]] = {i: [] for i in range(bucket_count)}
    for e in entries_meta:
        bucket_records[int(e["bucket_index"])].append(e)
    for rows in bucket_records.values():
        rows.sort(key=lambda e: int(e["bucket_order"]))

    bucket_sizes: list[int] = []
    for bi in range(bucket_count):
        size = 1
        for e in bucket_records[bi]:
            size += 5 + len(str(e["name"]).encode("ascii")) + 1
        bucket_sizes.append(size)

    header_size = 8 + bucket_count * 8
    bucket_offsets: list[int] = []
    p = header_size
    for size in bucket_sizes:
        bucket_offsets.append(p)
        p += size

    physical_entries = sorted(entries_meta, key=lambda e: int(e.get("original_offset", 0)))
    entry_offsets: dict[str, int] = {}
    q = p
    for e in physical_entries:
        name = str(e["name"])
        raw = raw_by_name[name]
        entry_offsets[name] = q
        q += 8 + len(raw)

    out = bytearray()
    out += b"Him5"
    out += struct.pack("<I", bucket_count)
    for bi in range(bucket_count):
        out += struct.pack("<II", bucket_sizes[bi], bucket_offsets[bi])
    for bi in range(bucket_count):
        block = bytearray()
        for e in bucket_records[bi]:
            name = str(e["name"])
            name_b = name.encode("ascii") + b"\0"
            rec_len = 5 + len(name_b)
            if rec_len > 0xFF:
                raise ValueError(f"bucket record too long: {name}")
            block.append(rec_len)
            block += entry_offsets[name].to_bytes(4, "big")
            block += name_b
        block.append(0)
        if len(block) != bucket_sizes[bi]:
            raise AssertionError((bi, len(block), bucket_sizes[bi]))
        out += block
    for e in physical_entries:
        name = str(e["name"])
        raw = raw_by_name[name]
        out += struct.pack("<II", 0, len(raw))
        out += raw
    return bytes(out)


def scan_cp932_strings(data: bytes, min_chars: int = 1, encoding: str = "cp932") -> list[tuple[int, int, str]]:
    res: list[tuple[int, int, str]] = []
    i = 0
    n = len(data)
    while i < n:
        start = i
        buf = bytearray()
        chars = 0
        ok = False
        while i < n:
            b = data[i]
            if b == 0:
                ok = True
                break
            if b in (0x0A, 0x0D, 0x09) or 0x20 <= b <= 0x7E:
                buf.append(b)
                i += 1
                chars += 1
                continue
            if (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xFC) and i + 1 < n:
                b2 = data[i + 1]
                if 0x40 <= b2 <= 0xFC and b2 != 0x7F:
                    buf += bytes([b, b2])
                    i += 2
                    chars += 1
                    continue
            ok = False
            break
        if ok and chars >= min_chars:
            try:
                text = bytes(buf).decode(encoding)
            except UnicodeDecodeError:
                text = ""
            if text:
                res.append((start, i + 1, text))
            i += 1
        else:
            i = start + 1
    return res


def looks_visible_text(text: str) -> bool:
    if not text or not text.strip():
        return False
    if ASCII_RESOURCE_RE.fullmatch(text):
        return False
    if RESOURCE_RE.fullmatch(text):
        return False
    return bool(JP_RE.search(text) or any(ord(c) > 0x7F for c in text))


def split_name_message(raw_text: str) -> tuple[str, str]:
    name, msg, _sep = split_name_message_ex(raw_text)
    return name, msg


def split_name_message_ex(raw_text: str) -> tuple[str, str, str]:
    if raw_text.startswith("【"):
        end = raw_text.find("】")
        if 1 <= end <= 64:
            rest = raw_text[end + 1 :]
            sep = ""
            if rest.startswith("\r\n"):
                sep = "\r\n"
                rest = rest[2:]
            elif rest.startswith("\n") or rest.startswith("\r"):
                sep = rest[0]
                rest = rest[1:]
            return raw_text[1:end], rest, sep
    return "", raw_text, ""


def compose_name_message(name: str, msg: str, sep: str = "\n") -> str:
    return f"【{name}】{sep}{msg}" if name else msg


def classify_context(data: bytes, start: int) -> str:
    lo = max(0, start - 80)
    prefix = data[lo:start]
    marker = prefix.rfind(b"\x0a\x0d")
    if marker >= 0 and marker + 3 < len(prefix):
        cmd = prefix[marker + 2]
        if cmd == 0x33:
            return "message"
        if cmd in (0x34, 0x36):
            return "choice"
        return f"cmd_{cmd:02x}"
    return "literal"


def load_text_jsons(text_dir: Path) -> list[dict[str, Any]]:
    """Load edited text JSONs.

    Preferred v3 format: one JSON per script:
      {"_file": "sc1_1", "texts": [{"name": "", "msg": "", "_offset": ...}, ...]}

    Backward compatible with older one-text-per-json files:
      {"name": "", "msg": "", "_file": "sc1_1", "_offset": ...}
    """
    items: list[dict[str, Any]] = []
    for path in sorted(text_dir.rglob("*.json")):
        if path.name.lower() == "manifest.json":
            continue
        obj = json.loads(path.read_text(encoding="utf-8"))

        if isinstance(obj, dict) and isinstance(obj.get("texts"), list):
            top_file = obj.get("_file") or path.stem
            for idx, row in enumerate(obj["texts"]):
                if not isinstance(row, dict):
                    continue
                if "_offset" not in row:
                    continue
                item = dict(row)
                item.setdefault("_file", top_file)
                item.setdefault("_index", idx)
                item["_json_path"] = f"{path}#{idx}"
                items.append(item)
            continue

        if isinstance(obj, list):
            top_file = path.stem
            for idx, row in enumerate(obj):
                if not isinstance(row, dict) or "_offset" not in row:
                    continue
                item = dict(row)
                item.setdefault("_file", top_file)
                item.setdefault("_index", idx)
                item["_json_path"] = f"{path}#{idx}"
                items.append(item)
            continue

        if isinstance(obj, dict) and "_file" in obj and "_offset" in obj:
            obj["_json_path"] = str(path)
            items.append(obj)
    return items
