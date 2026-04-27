"""
AI6WIN MES disassembler.

Walks the body and produces a list of instructions in order, each tagged with
its raw body-relative offset. Offset-carrying operands are resolved to label
references so the re-assembler can place the target wherever it needs to in
the new byte stream.

This module is deliberately format-agnostic — the extractor/injector pick it
up and choose their own on-disk representation (JSON for translation, text
dump for debugging, etc.).

Output of `disassemble()`:
    {
        "message_count": int,              # prm[0] from header
        "first_offsets": [raw_off, ...],   # header entries, length == count
        "instructions": [
            {
                "raw_off": int,            # body-relative offset of this op
                "op": int,
                "mnemonic": str,
                "args": [...],             # decoded args, offsets replaced by
                                           #   {"label": raw_off_of_target}
            },
            ...
        ],
        "trailing": bytes,                 # anything unrecognized at the tail
    }

A label is simply the raw_off of an instruction elsewhere in the stream. The
assembler recomputes each instruction's raw_off after writing it, then
patches labels into concrete u32 offsets.
"""

from __future__ import annotations

import struct
from typing import Any

from mes_opcodes import (
    ENCODING,
    MESSAGE_OPCODE,
    OFFSET_OPCODES,
    OPCODES,
    STRING_OPCODES,
)


HEADER_COUNT_SIZE = 4
OFFSET_ENTRY_SIZE = 4


def body_base(message_count: int) -> int:
    """Where the bytecode body starts, given the header's message count."""
    return HEADER_COUNT_SIZE + message_count * OFFSET_ENTRY_SIZE


def read_header(buf: bytes) -> tuple[int, list[int]]:
    """Return (message_count, first_offsets) from the header."""
    if len(buf) < HEADER_COUNT_SIZE:
        raise ValueError("file too small for header")
    count = struct.unpack_from("<I", buf, 0)[0]
    if count > 0x10000:
        raise ValueError(f"unreasonable message_count: {count}")
    # count == 0 is legal: non-dialogue scripts like FLAGINI.mes carry only
    # bytecode (flag init, menus, etc.) with no MESSAGE boundaries in the header.
    need = HEADER_COUNT_SIZE + count * OFFSET_ENTRY_SIZE
    if len(buf) < need:
        raise ValueError(f"header truncated (need {need:#x}, have {len(buf):#x})")
    first = [
        struct.unpack_from("<I", buf, HEADER_COUNT_SIZE + i * OFFSET_ENTRY_SIZE)[0]
        for i in range(count)
    ]
    return count, first


def _read_string(buf: bytes, pos: int) -> tuple[str, int]:
    """Read a NUL-terminated CP932 string. Return (text, pos_after_nul)."""
    end = pos
    n = len(buf)
    while end < n and buf[end] != 0:
        end += 1
    if end >= n:
        raise ValueError(f"unterminated string at {pos:#x}")
    raw = bytes(buf[pos:end])
    try:
        text = raw.decode(ENCODING)
    except UnicodeDecodeError as e:
        # Log the offset but keep a lossy decode — makes debugging easier
        # than aborting the whole pass.
        text = raw.decode(ENCODING, errors="replace")
    return text, end + 1  # skip the NUL


def _decode_args(
    buf: bytes,
    pos: int,
    spec: str,
    op: int,
) -> tuple[list[Any], int]:
    """Decode args per spec string. Returns (args, pos_after_args)."""
    args: list[Any] = []
    i = 0
    while i < len(spec):
        c = spec[i]
        if c == ">":
            # Two-char token: >I or >i
            tok = spec[i : i + 2]
            i += 2
            if tok == ">I":
                (v,) = struct.unpack_from(">I", buf, pos)
                pos += 4
            elif tok == ">i":
                (v,) = struct.unpack_from(">i", buf, pos)
                pos += 4
            else:
                raise ValueError(f"bad spec token {tok!r} for op {op:#x}")
            args.append(v)
        elif c == "B":
            args.append(buf[pos])
            pos += 1
            i += 1
        elif c == "S":
            text, pos = _read_string(buf, pos)
            args.append(text)
            i += 1
        else:
            raise ValueError(f"unknown spec char {c!r} for op {op:#x}")
    return args, pos


def disassemble(buf: bytes) -> dict[str, Any]:
    """Disassemble an AI6WIN MES file (raw CP932 bytes, LZSS already undone)."""
    count, first_offsets = read_header(buf)
    base = body_base(count)

    instructions: list[dict[str, Any]] = []
    pc = base
    n = len(buf)

    # Known raw offsets that any instruction might reference (jump targets).
    # We'll resolve them into labels in a second pass — for now just collect.
    while pc < n:
        op = buf[pc]
        raw_off = pc - base
        info = OPCODES.get(op)
        if info is None:
            # Unknown opcode — stop and keep trailing bytes as-is.
            break
        spec, mnem = info
        op_pc = pc
        pc += 1
        try:
            args, pc = _decode_args(buf, pc, spec, op)
        except Exception as e:
            raise ValueError(
                f"failed to decode op {op:#x} ({mnem}) at file offset {op_pc:#x}: {e}"
            ) from e

        # Wrap offset operands as label refs for the assembler's benefit.
        if op in OFFSET_OPCODES:
            args[0] = {"label": int(args[0])}

        instructions.append({
            "raw_off": raw_off,
            "op": op,
            "mnemonic": mnem,
            "args": args,
        })

    trailing = bytes(buf[pc:])

    return {
        "message_count": count,
        "first_offsets": first_offsets,
        "instructions": instructions,
        "trailing": trailing,
        "body_base": base,
    }


def validate(dis: dict[str, Any]) -> None:
    """Sanity-check a disassembly result.

    - Every MESSAGE opcode's raw_off should appear in first_offsets, in order.
    - Every jump/choice label should point at some instruction's raw_off
      (or, rarely, at the end of the body for early-exit jumps).
    """
    count = dis["message_count"]
    first = dis["first_offsets"]
    instrs = dis["instructions"]

    # 1. Messages match header.
    msg_offs = [i["raw_off"] for i in instrs if i["op"] == MESSAGE_OPCODE]
    if msg_offs != first:
        if len(msg_offs) != len(first):
            raise ValueError(
                f"MESSAGE count mismatch: body has {len(msg_offs)}, "
                f"header has {len(first)}"
            )
        for idx, (a, b) in enumerate(zip(msg_offs, first)):
            if a != b:
                raise ValueError(
                    f"message {idx}: body offset {a:#x} != header {b:#x}"
                )

    # 2. Labels land on known instruction boundaries.
    known = {i["raw_off"] for i in instrs}
    end_of_body = instrs[-1]["raw_off"] + _instruction_encoded_size(instrs[-1]) \
        if instrs else 0
    for ins in instrs:
        if ins["op"] not in OFFSET_OPCODES:
            continue
        tgt = ins["args"][0]["label"]
        if tgt in known or tgt == end_of_body:
            continue
        raise ValueError(
            f"{ins['mnemonic']} at {ins['raw_off']:#x} "
            f"targets unknown offset {tgt:#x}"
        )


def _instruction_encoded_size(ins: dict[str, Any]) -> int:
    """Byte size of an instruction when re-encoded."""
    spec, _ = OPCODES[ins["op"]]
    size = 1  # opcode byte
    i = 0
    ai = 0
    while i < len(spec):
        c = spec[i]
        if c == ">":
            size += 4
            i += 2
            ai += 1
        elif c == "B":
            size += 1
            i += 1
            ai += 1
        elif c == "S":
            val = ins["args"][ai]
            text = val if isinstance(val, str) else val.decode(ENCODING)
            size += len(text.encode(ENCODING)) + 1
            i += 1
            ai += 1
        else:
            raise ValueError(f"bad spec {c!r}")
    return size


if __name__ == "__main__":
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        print("usage: python mes_diss.py <plaintext.mes>")
        sys.exit(1)

    data = Path(sys.argv[1]).read_bytes()
    dis = disassemble(data)
    validate(dis)

    print(f"message_count: {dis['message_count']}")
    print(f"body_base:     {dis['body_base']:#x}")
    print(f"instructions:  {len(dis['instructions'])}")
    print(f"trailing:      {len(dis['trailing'])} bytes")
    # Opcode histogram
    from collections import Counter
    hist = Counter(i["op"] for i in dis["instructions"])
    print("\ntop opcodes:")
    for op, c in hist.most_common(15):
        mnem = OPCODES[op][1]
        print(f"  {op:#04x} {mnem:<16} x {c}")

    # Count strings
    nstr = sum(1 for i in dis["instructions"] if i["op"] in STRING_OPCODES)
    ntxt = sum(1 for i in dis["instructions"] if i["op"] == 0x0A)
    print(f"\ntotal strings: {nstr}  (of which STR_PRIMARY / 0x0A: {ntxt})")
