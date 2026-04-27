"""
AI6WIN MES script opcode table (version 1, "most games").

Derived from:
  - silky_mes_tools AI6WINScript.command_library v1
  - Cross-validated by full static disassembly of stage00.mes
    (0xb8e8 bytes fully consumed, 639 jump/choice targets all landing in-file)

File layout:
  [0x00]  u32 LE          message_count (= number of 0x19 MESSAGE opcodes in body)
  [0x04]  u32 LE × count  first_offsets[] — raw offsets relative to body base,
                          pointing at each MESSAGE instruction in order
  [0x04 + count*4]        bytecode body

Bytecode endianness: every multi-byte numeric operand inside the body is
big-endian (struct.pack('>I', ...)). Only the header is little-endian.

Offset-carrying opcodes (arg[0] is a raw body-relative offset):
  0x14 JUMP_IF_ZERO
  0x15 JUMP
  0x16 LIBREG
  0x1A CHOICE

Special:
  0x19 MESSAGE  arg[0] is a 0-based message index, NOT an offset.
"""

from __future__ import annotations


# opcode -> (args_spec, mnemonic)
#   args_spec is a string composed of tokens:
#     '>I'  = big-endian u32   (raw offset or unsigned immediate)
#     '>i'  = big-endian s32   (signed immediate, used by PUSH_INT32)
#     'B'   = u8
#     'S'   = CP932 NUL-terminated string (inline in bytecode)
OPCODES: dict[int, tuple[str, str]] = {
    0x00: ("",    "YIELD"),
    0x01: ("",    "RETURN"),
    0x02: ("",    "LGDLOB1_I8"),
    0x03: ("",    "LGDLOB2_I16"),
    0x04: ("",    "LGDLOB3_VAR"),
    0x05: ("",    "LGDLOB4_VAR"),
    0x06: ("",    "LDLOC_VAR"),
    0x07: ("",    "LGDLOB5_I8"),
    0x08: ("",    "LGDLOB5_I16"),
    0x09: ("",    "LGDLOB5_I32"),
    0x0A: ("S",   "STR_PRIMARY"),
    0x0B: ("S",   "STR_SUPPLEMENT"),
    0x0C: ("",    "STGLOB1_I8"),
    0x0D: ("",    "STGLOB2_I16"),
    0x0E: ("",    "STGLOB3_VAR"),
    0x0F: ("",    "STGLOB4_VAR"),

    0x10: ("B",   "STLOC_VAR"),
    0x11: ("",    "STGLOB5_I8"),
    0x12: ("",    "STGLOB6_I16"),
    0x13: ("",    "STGLOB7_I32"),
    0x14: (">I",  "JUMP_IF_ZERO"),
    0x15: (">I",  "JUMP"),
    0x16: (">I",  "LIBREG"),
    0x17: ("",    "LIBCALL"),
    0x18: ("",    "SYSCALL"),
    0x19: (">I",  "MESSAGE"),
    0x1A: (">I",  "CHOICE"),
    0x1B: ("B",   "ESCAPE"),
    0x1D: ("",    "OP_1D"),

    0x32: (">i",  "PUSH_INT32"),
    0x33: ("S",   "PUSH_STR"),
    0x34: ("",    "ADD"),
    0x35: ("",    "SUB"),
    0x36: ("B",   "MUL"),
    0x37: ("",    "DIV"),
    0x38: ("",    "MOD"),
    0x39: ("",    "RAND"),
    0x3A: ("",    "LOGICAL_AND"),
    0x3B: ("",    "LOGICAL_OR"),
    0x3C: ("",    "BINARY_AND"),
    0x3D: ("",    "BINARY_OR"),
    0x3E: ("",    "LT"),
    0x3F: ("",    "GT"),

    0x40: ("",    "LE"),
    0x41: ("",    "GE"),
    0x42: ("",    "EQ"),
    0x43: ("",    "NEQ"),

    0xFA: ("",    "OP_FA"),
    0xFB: ("",    "OP_FB"),
    0xFC: ("",    "OP_FC"),
    0xFD: ("",    "OP_FD"),
    0xFE: ("",    "OP_FE"),
    0xFF: ("",    "OP_FF"),
}

# Opcodes whose first u32 operand is a raw offset that must be fixed up on
# variable-length injection.
OFFSET_OPCODES = {0x14, 0x15, 0x16, 0x1A}

# Opcodes containing an inline CP932 NUL-terminated string.
STRING_OPCODES = {0x0A, 0x0B, 0x33}

# Opcodes that correspond to a "message boundary" — the header's first_offsets
# array points at each 0x19 in the body.
MESSAGE_OPCODE = 0x19

ENCODING = "cp932"
