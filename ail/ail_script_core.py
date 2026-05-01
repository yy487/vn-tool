#!/usr/bin/env python3
"""Generic AILSystem script parser used by JSON extract/inject tools.

The parser keeps the old BONDAGE JSON workflow, but uses AIL_Tools-style
function opcode tables and expression consumption so it is no longer tied to a
small hand-written subset of sub opcodes.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ail_opcode_tables import FUNC_TABLES


NAME_TAG_RE = re.compile(r'^【([^】]{1,32})】$')
EXPR_OPERATORS = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0A, 0x0B, 0x0C, 0x14, 0x15, 0x16, 0x17, 0x18}


class ParseError(Exception):
    """Raised when an instruction cannot be consumed safely."""


@dataclass
class TextRef:
    pc: int              # main opcode pc, relative to bytecode start
    func_pc: int         # function/sub-op pc, relative to bytecode start
    ref_pc: int          # u16 string reference pc, relative to bytecode start
    sub: int             # function/sub opcode
    text_off: int        # string-pool relative offset
    message: str
    kind: str
    op_name: str


# Existing project semantics. Generic AIL does not know which opcodes mean
# speaker names or UI strings, but these overrides preserve the old workflow for
# BONDAGE-like scripts while remaining harmless for other games.
BONDAGE_TITLE_SUBOPS = {0x08, 0x09, 0x0D, 0x6E}


MAIN_FLOWS = {
    0x00: 'seq',  # exec_func
    0x04: 'seq',  # store_v expr
    0x05: 'seq',  # store_f func
    0x08: 'end',  # jump
    0x09: 'seq',  # switch
    0x0A: 'seq',  # load_script expr
    0x0B: 'seq',  # call expr expr
    0x0C: 'end',  # jump_label expr
    0x0D: 'end',  # ret
    0x10: 'seq',  # call_script expr expr expr
    0x11: 'end',  # exit / stop-like in most samples
    0x12: 'seq',  # jump_true expr target
}


class ScriptParser:
    def __init__(self, data: bytes, *, version: int = 2, encoding: str = 'cp932', profile: str = 'generic',
                 validate_expr_ops: bool = False):
        if version not in FUNC_TABLES:
            raise ValueError(f'unsupported AIL script version: {version}')
        if profile not in ('generic', 'bondage'):
            raise ValueError("profile must be 'generic' or 'bondage'")
        self.data = data
        self.version = version
        self.encoding = encoding
        self.profile = profile
        self.validate_expr_ops = validate_expr_ops
        self.hdr = parse_header(data)
        self.labels = parse_labels(data, self.hdr)
        self.pc = 0
        self.func_table = FUNC_TABLES[version]

    @property
    def bc_base(self) -> int:
        return self.hdr['bc_base']

    @property
    def bc_size(self) -> int:
        return self.hdr['bc_size']

    @property
    def text_base(self) -> int:
        return self.hdr['text_base']

    @property
    def text_size(self) -> int:
        return max(0, len(self.data) - self.text_base)

    def clone_at(self, pc: int) -> 'ScriptParser':
        w = ScriptParser(self.data, version=self.version, encoding=self.encoding, profile=self.profile,
                         validate_expr_ops=self.validate_expr_ops)
        w.pc = pc
        return w

    def need(self, n: int):
        if self.pc + n > self.bc_size:
            raise ParseError(f'EOF while reading {n} byte(s) at pc={self.pc:#x}')

    def u8(self) -> int:
        self.need(1)
        v = self.data[self.bc_base + self.pc]
        self.pc += 1
        return v

    def u16(self) -> int:
        self.need(2)
        v = struct.unpack_from('<H', self.data, self.bc_base + self.pc)[0]
        self.pc += 2
        return v

    def u16_ref(self) -> Tuple[int, int]:
        ref_pc = self.pc
        return self.u16(), ref_pc

    def consume_expr(self):
        """Consume one AIL expression exactly like AIL_Tools ParseExpression.

        Expression stream:
          * 0x00 reg u16-mask loads a variable and may repeat
          * 0xFF terminates the expression
          * any other flag byte is followed by one operator byte
        """
        while True:
            while True:
                flag = self.u8()
                if flag != 0:
                    break
                self.u8()   # reg
                self.u16()  # mask
            if flag == 0xFF:
                return
            op = self.u8()
            if self.validate_expr_ops and op not in EXPR_OPERATORS:
                raise ParseError(f'unexpected expression operator {op:#x} at pc={self.pc-1:#x}')

    def consume_switch(self):
        self.u8()   # reg
        self.u16()  # mask
        self.u16()  # default target
        count = self.u8()
        for _ in range(count):
            self.u8()   # branch id
            self.u16()  # branch target

    def read_str(self, text_off: int) -> str:
        if text_off < 0 or text_off >= self.text_size:
            raise ParseError(f'string offset out of range: {text_off:#x} / pool={self.text_size:#x}')
        start = self.text_base + text_off
        try:
            end = self.data.index(b'\x00', start)
        except ValueError:
            end = len(self.data)
        return self.data[start:end].decode(self.encoding, errors='replace')

    def classify(self, sub: int, text: str) -> str:
        if sub in (0x00, 0x01):
            return 'msg'
        if self.profile == 'bondage' and sub in BONDAGE_TITLE_SUBOPS:
            return 'title'
        return 'msg_other'

    def parse_func(self, main_pc: int) -> List[TextRef]:
        func_pc = self.pc
        sub = self.u8()
        if sub not in self.func_table:
            raise ParseError(f'unknown function opcode {sub:#x} at pc={func_pc:#x}')
        events: List[TextRef] = []
        for action in self.func_table[sub]:
            if action == 'expr':
                self.consume_expr()
            elif action == 'text':
                text_off, ref_pc = self.u16_ref()
                text = self.read_str(text_off)
                kind = self.classify(sub, text)
                events.append(TextRef(
                    pc=main_pc, func_pc=func_pc, ref_pc=ref_pc, sub=sub, text_off=text_off,
                    message=text, kind=kind, op_name=f'FUNC_{sub:02X}'
                ))
            else:
                raise ParseError(f'bad function action {action!r}')
        return events

    def parse_main(self) -> Tuple[str, List[TextRef]]:
        op_pc = self.pc
        op = self.u8()
        events: List[TextRef] = []
        if op == 0x00:
            events.extend(self.parse_func(op_pc))
        elif op == 0x04:
            self.u8(); self.u16(); self.consume_expr()
        elif op == 0x05:
            self.u8(); self.u16(); events.extend(self.parse_func(op_pc))
        elif op == 0x08:
            self.u16()
        elif op == 0x09:
            self.consume_switch()
        elif op == 0x0A:
            self.consume_expr()
        elif op == 0x0B:
            self.consume_expr(); self.consume_expr()
        elif op == 0x0C:
            self.consume_expr()
        elif op == 0x0D:
            pass
        elif op == 0x10:
            self.consume_expr(); self.consume_expr(); self.consume_expr()
        elif op == 0x11:
            pass
        elif op == 0x12:
            self.consume_expr(); self.u16()
        else:
            # AIL_Tools treats non-zero trailing bytes as an error. Be lenient
            # for zero padding near the end of code.
            rest = self.data[self.bc_base + op_pc:self.bc_base + self.bc_size]
            if rest and all(b == 0 for b in rest):
                self.pc = self.bc_size
                return 'end', []
            raise ParseError(f'unknown main opcode {op:#x} at pc={op_pc:#x}')
        return MAIN_FLOWS.get(op, 'seq'), events

    def scan_block(self, start_pc: int, *, stop_on_flow: bool = True, resync: bool = False) -> Tuple[List[TextRef], Optional[str]]:
        self.pc = start_pc
        visited = set()
        events: List[TextRef] = []
        while self.pc < self.bc_size:
            if stop_on_flow and self.pc in visited:
                break
            visited.add(self.pc)
            old_pc = self.pc
            try:
                flow, evs = self.parse_main()
                events.extend(evs)
                if stop_on_flow and flow == 'end':
                    break
            except ParseError as e:
                if resync and old_pc + 1 < self.bc_size:
                    self.pc = old_pc + 1
                    continue
                return events, str(e)
        return events, None

    def scan_events(self, *, mode: str = 'both', resync: bool = False) -> Tuple[List[TextRef], Dict[str, int]]:
        if mode not in ('labels', 'linear', 'both'):
            raise ValueError("mode must be 'labels', 'linear', or 'both'")
        events: List[TextRef] = []
        stats = {'blocks': 0, 'failed_blocks': 0, 'linear_failed': 0}
        seen_ref_pc = set()

        def add(evs: Iterable[TextRef]):
            for e in evs:
                if e.ref_pc in seen_ref_pc:
                    continue
                seen_ref_pc.add(e.ref_pc)
                events.append(e)

        if mode in ('labels', 'both'):
            for _, start in sorted(self.labels.items()):
                stats['blocks'] += 1
                w = self.clone_at(start)
                evs, err = w.scan_block(start, stop_on_flow=True, resync=resync)
                add(evs)
                if err:
                    stats['failed_blocks'] += 1
        if mode in ('linear', 'both'):
            w = self.clone_at(0)
            evs, err = w.scan_block(0, stop_on_flow=False, resync=resync)
            add(evs)
            if err:
                stats['linear_failed'] += 1
        events.sort(key=lambda x: (x.pc, x.func_pc, x.ref_pc))
        stats['events'] = len(events)
        return events, stats

    def collect_refs(self, *, mode: str = 'both', resync: bool = False) -> Tuple[Dict[int, List[Tuple[int, str, int]]], Dict[str, int]]:
        events, stats = self.scan_events(mode=mode, resync=resync)
        refs: Dict[int, List[Tuple[int, str, int]]] = {}
        for e in events:
            refs.setdefault(e.text_off, []).append((e.ref_pc, e.kind, e.sub))
        stats['unique_text_offsets'] = len(refs)
        return refs, stats


def parse_header(data: bytes) -> dict:
    if len(data) < 12:
        raise ValueError('file too small for AIL script header')
    signature = struct.unpack_from('<I', data, 0)[0]
    label_len = struct.unpack_from('<H', data, 4)[0]
    code_len = struct.unpack_from('<H', data, 6)[0]
    if signature != 0:
        raise ValueError(f'not an AIL script header: signature={signature:#x}')
    index_base = 0x0C
    bc_base = index_base + label_len
    text_base = bc_base + code_len
    return {
        'signature': signature,
        'label_len': label_len,
        'label_count': label_len // 4,
        # compatibility with old tool names
        'index_slots': label_len // 2,
        'text_rel': code_len,
        'code_len': code_len,
        'index_base': index_base,
        'bc_base': bc_base,
        'text_base': text_base,
        'bc_size': code_len,
    }


def parse_labels(data: bytes, hdr: dict) -> dict:
    labels = {}
    for i in range(hdr['label_count']):
        off = hdr['index_base'] + i * 4
        lid = struct.unpack_from('<H', data, off)[0]
        pc = struct.unpack_from('<H', data, off + 2)[0]
        if lid or pc:
            labels[lid] = pc
    return labels


def iter_cstring_offsets(data: bytes, hdr: dict) -> List[int]:
    offs = []
    i = hdr['text_base']
    while i < len(data):
        j = i
        while j < len(data) and data[j] != 0:
            j += 1
        rel = i - hdr['text_base']
        if j > i:
            offs.append(rel)
        while j < len(data) and data[j] == 0:
            j += 1
        i = j
    return offs


def read_pool_string(data: bytes, hdr: dict, text_off: int, encoding: str = 'cp932') -> str:
    start = hdr['text_base'] + text_off
    end = data.index(0, start) if start < len(data) and 0 in data[start:] else len(data)
    return data[start:end].decode(encoding, errors='replace')


def pair_name_msg(events: Sequence[TextRef]) -> List[dict]:
    """Merge [MSG '【Name】', MSG 'line'] into one JSON entry with name fields."""
    result: List[dict] = []
    skip = set()
    raw = sorted(events, key=lambda e: (e.pc, e.func_pc, e.ref_pc))
    for i, e in enumerate(raw):
        if i in skip:
            continue
        if e.kind == 'msg':
            m = NAME_TAG_RE.match(e.message)
            if m and i + 1 < len(raw) and raw[i + 1].kind == 'msg' and not NAME_TAG_RE.match(raw[i + 1].message):
                nxt = raw[i + 1]
                item = textref_to_entry(nxt)
                item['name'] = m.group(1)
                item['name_pc'] = e.pc
                item['name_text_off'] = e.text_off
                result.append(item)
                skip.add(i + 1)
                continue
        result.append(textref_to_entry(e))
    for idx, item in enumerate(result):
        item['id'] = idx
    return result


def textref_to_entry(e: TextRef) -> dict:
    return {
        'id': -1,
        'pc': e.pc,
        'sub': e.sub,
        'kind': e.kind,
        'text_off': e.text_off,
        'message': e.message,
        'src_msg': e.message,
    }


def apply_text_map(s: str, mapping: Optional[dict]) -> str:
    if not mapping:
        return s
    # longest keys first supports both char-level and phrase-level maps
    for k in sorted(mapping.keys(), key=len, reverse=True):
        s = s.replace(k, str(mapping[k]))
    return s


def encode_cstring(s: str, *, encoding: str = 'cp932', errors: str = 'replace', mapping: Optional[dict] = None,
                   align: int = 2) -> bytes:
    s = apply_text_map(s, mapping)
    b = s.encode(encoding, errors=errors) + b'\x00'
    if align > 1:
        while len(b) % align:
            b += b'\x00'
    return b


def safe_truncate_encoded(encoded: bytes, max_len: int, *, encoding: str = 'cp932') -> bytes:
    """Truncate encoded string without splitting common Shift-JIS/CP932 double-byte sequences."""
    if max_len <= 0:
        return b''
    truncated = encoded[:max_len]
    if encoding.lower().replace('-', '') in ('cp932', 'shiftjis', 'shift_jis', 'sjis'):
        fixed = bytearray()
        i = 0
        while i < len(truncated):
            b = truncated[i]
            if (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC):
                if i + 1 >= len(truncated):
                    break
                fixed.extend(truncated[i:i+2]); i += 2
            else:
                fixed.append(b); i += 1
        return bytes(fixed)
    # generic conservative fallback: shorten until it decodes
    out = truncated
    while out:
        try:
            out.decode(encoding)
            return out
        except UnicodeDecodeError:
            out = out[:-1]
    return b''
