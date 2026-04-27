"""
AI6WIN MES assembler — inverse of mes_diss.disassemble().

Takes the disassembly dict (with possibly-modified string args) and emits a
valid .mes byte stream. Performs variable-length-safe offset fix-up in two
passes:

  Pass 1: Walk the instruction stream. For each instruction, record its new
          raw offset, then emit placeholder bytes (offsets filled in with 0).
          Also rebuild first_offsets by picking up the new raw_off of each
          MESSAGE instruction.

  Pass 2: Walk the emitted body again, overwriting every offset operand
          (opcodes 0x14/0x15/0x16/0x1A) with the new raw offset of the
          labelled target instruction.

This scheme is safe as long as OPCODES + OFFSET_OPCODES fully enumerates the
offset-carrying opcodes in the engine — which, per the decompiled exe and
the silky_mes library, they do for AI6WIN v1.
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
from mes_diss import (
    HEADER_COUNT_SIZE,
    OFFSET_ENTRY_SIZE,
    body_base,
)


def _encode_args(ins: dict[str, Any]) -> tuple[bytes, list[tuple[int, str]]]:
    """Encode a single instruction's args.

    Returns (bytes, patchlist), where patchlist is a list of
    (offset_within_instruction, label_ref) entries for offset operands.
    The offset bytes are emitted as placeholder 00 00 00 00; the caller
    overwrites them in Pass 2.
    """
    spec, _ = OPCODES[ins["op"]]
    buf = bytearray()
    patches: list[tuple[int, int]] = []
    i = 0
    ai = 0
    # Track position within the encoded instruction (1 = just after opcode byte).
    cur_ins_pos = 1
    while i < len(spec):
        c = spec[i]
        if c == ">":
            tok = spec[i : i + 2]
            i += 2
            val = ins["args"][ai]
            ai += 1
            if tok == ">I":
                if isinstance(val, dict) and "label" in val:
                    patches.append((cur_ins_pos, val["label"]))
                    buf += b"\x00\x00\x00\x00"
                else:
                    buf += struct.pack(">I", int(val) & 0xFFFFFFFF)
            elif tok == ">i":
                buf += struct.pack(">i", int(val))
            else:
                raise ValueError(f"bad spec {tok!r}")
            cur_ins_pos += 4
        elif c == "B":
            buf += struct.pack("B", int(ins["args"][ai]) & 0xFF)
            ai += 1
            cur_ins_pos += 1
            i += 1
        elif c == "S":
            text = ins["args"][ai]
            if not isinstance(text, str):
                raise TypeError(
                    f"string arg of op {ins['op']:#x} must be str, "
                    f"got {type(text).__name__}"
                )
            enc = text.encode(ENCODING)
            if b"\x00" in enc:
                raise ValueError(
                    f"string contains embedded NUL: {text!r}"
                )
            buf += enc
            buf += b"\x00"
            ai += 1
            cur_ins_pos += len(enc) + 1
            i += 1
        else:
            raise ValueError(f"unknown spec char {c!r}")
    return bytes(buf), patches


def assemble(dis: dict[str, Any]) -> bytes:
    """Assemble a disassembly dict back into a .mes byte stream.

    The dict must still have "instructions" (possibly with modified string
    args), "message_count" (will be recomputed if MESSAGE count changes),
    and "trailing" (preserved verbatim).
    """
    instrs = dis["instructions"]

    # Recompute message count from actual MESSAGE instructions, in case the
    # caller added/removed any. AI6 engine expects prm[0] == count of 0x19.
    message_count = sum(1 for i in instrs if i["op"] == MESSAGE_OPCODE)

    base = body_base(message_count)

    # Pass 1: encode every instruction; record new raw offsets and patches.
    body = bytearray()
    # label (old raw_off) -> new raw_off
    label_map: dict[int, int] = {}
    # For each patch: (absolute_body_offset, label_to_resolve)
    pending: list[tuple[int, int]] = []
    # For each MESSAGE instruction: the new raw offset, in body order.
    new_first_offsets: list[int] = []

    for ins in instrs:
        new_raw_off = len(body)
        old_raw_off = ins.get("raw_off")
        if old_raw_off is not None:
            label_map[old_raw_off] = new_raw_off
        ins_bytes, patches = _encode_args(ins)
        # Opcode byte
        body.append(ins["op"])
        # Args
        for patch_pos, label in patches:
            pending.append((new_raw_off + patch_pos, label))
        body += ins_bytes
        if ins["op"] == MESSAGE_OPCODE:
            new_first_offsets.append(new_raw_off)

    # Label = "end of body" is occasionally used by early-exit jumps.
    # We treat any label not in label_map but equal to end-of-old-body
    # as pointing to end-of-new-body.
    end_of_new_body = len(body)
    # Compute end of old body for the reverse mapping.
    end_of_old_body = 0
    if instrs:
        last = instrs[-1]
        end_of_old_body = last.get("raw_off", 0) + _old_ins_size(last)

    # Pass 2: resolve label patches.
    for abs_pos, label in pending:
        if label in label_map:
            tgt = label_map[label]
        elif label == end_of_old_body:
            tgt = end_of_new_body
        else:
            raise ValueError(
                f"unresolved label {label:#x} "
                f"(patch at body {abs_pos:#x})"
            )
        struct.pack_into(">I", body, abs_pos, tgt)

    # Sanity: header MESSAGE count must match new_first_offsets length.
    if len(new_first_offsets) != message_count:
        raise AssertionError(
            f"internal: first_offsets {len(new_first_offsets)} != count {message_count}"
        )

    # Build header + body + trailing.
    out = bytearray()
    out += struct.pack("<I", message_count)
    for off in new_first_offsets:
        out += struct.pack("<I", off)
    assert len(out) == base, f"header size {len(out):#x} != base {base:#x}"
    out += body
    out += dis.get("trailing", b"")
    return bytes(out)


def _old_ins_size(ins: dict[str, Any]) -> int:
    """Byte size of an instruction as originally disassembled.

    Used to compute the position just past the last instruction — some
    early-exit jumps target that position.
    """
    spec, _ = OPCODES[ins["op"]]
    size = 1
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
            if not isinstance(val, str):
                raise TypeError("string arg must be str")
            size += len(val.encode(ENCODING)) + 1
            i += 1
            ai += 1
    return size


if __name__ == "__main__":
    # Round-trip self-test: disassemble stage00, re-assemble, byte-compare.
    import hashlib
    import sys
    from pathlib import Path
    from mes_diss import disassemble, validate

    if len(sys.argv) != 2:
        print("usage: python mes_asm.py <plaintext.mes>")
        sys.exit(1)
    src = Path(sys.argv[1]).read_bytes()
    dis = disassemble(src)
    validate(dis)
    out = assemble(dis)
    if out == src:
        print(f"PASS: byte-perfect round-trip ({len(src)} bytes, "
              f"md5={hashlib.md5(src).hexdigest()})")
    else:
        # Diagnostics
        print(f"FAIL: lengths {len(src)} vs {len(out)}")
        n = min(len(src), len(out))
        for i in range(n):
            if src[i] != out[i]:
                print(f"  first diff at {i:#x}")
                lo = max(0, i - 8)
                print(f"    orig: {src[lo:lo+24].hex(' ')}")
                print(f"    new:  {out[lo:lo+24].hex(' ')}")
                break
        sys.exit(1)
