#!/usr/bin/env python3
"""BONDAGE 引擎 OP 表 - 提取与注入共用

设计原则:
1. op/sub_op 的字节布局在此集中定义, 提取器和注入器只读这张表
2. "字段消费" 模型: 每条指令 = 定长字段序列, 用 (类型, 数量) 描述
3. 字段类型:
   - 'u8'     : 读/写 1 字节
   - 'u16'    : 读/写 2 字节
   - 'flag'   : 3 字节 (FUN_00430d90: u8 flag_idx + u16 mask)
   - 'expr'   : 变长, 直到 0xFF 终止
   - 'text'   : u16, 但语义是文本池偏移 (注入时需重映射)
   - 'name_text': u16 文本偏移, 同时更新 name 状态
   - 'switch_table': 变长 SWITCH 指令尾部
"""

# ============================================================
# 主 OP 表 (FUN_0042b550 调度器 - case 分支)
# ============================================================
# 格式: op -> ('助记符', [字段列表], 控制流标志)
# 控制流: 'seq'=顺序, 'end'=中止扫描(JMP/RET/EXIT)
MAIN_OPS = {
    0x00: ('MSG',          'dispatch_sub',          'seq'),  # 走子分派
    0x04: ('FLAG_SET_EXPR', [('u8',1),('u16',1),('expr',1)], 'seq'),
    0x05: ('FLAG_SET_MSG', [('u8',1),('u16',1)],    'end'),  # 之后走 sub_dispatch, 简化为 end
    0x08: ('JMP',          [('u16',1)],             'end'),
    0x09: ('SWITCH',       [('switch_table',1)],    'seq'),
    0x0A: ('CALL_LABEL',   [('u16',1)],             'seq'),
    0x0B: ('CALL_FRAME',   [('u16',1),('u16',1)],   'seq'),
    0x0C: ('JMP_LABEL',    [('u16',1)],             'end'),
    0x0D: ('RET',          [],                      'end'),
    0x10: ('CALL_WITH_FRAME',[('u16',1),('u16',1),('u16',1)],'seq'),
    0x11: ('EXIT',         [],                      'end'),
    0x12: ('JZ',           [('expr',1),('u16',1)],  'seq'),
}

# ============================================================
# 消息子 OP 表 (FUN_0042bcd0 子分派)
# ============================================================
# 格式: sub_op -> ('助记符', [字段列表], kind)
# kind:
#   'msg'      - 显示台词 (提取为消息)
#   'name'     - 设置当前说话人 (更新 state, 不作为台词输出)
#   'msg_other' - 含文本但非主台词 (章节标题/选择支等, 仍提取以便翻译)
#   'other'    - 不含文本, 单纯消费字节
SUB_OPS = {
    # --- 消息显示 ---
    0x00: ('MSG_CONT',       [('flag',1),('text',1)],          'msg'),
    0x01: ('MSG_NEW',        [('flag',1),('text',1)],          'msg'),
    # --- 说话人设置 (三变体) ---
    0x08: ('SET_NAME_FULL',  [('flag',4),('name_text',1)],     'name'),
    0x09: ('SET_NAME_DLG',   [('flag',4),('name_text',1)],     'name'),
    0x0D: ('SET_NAME_SHORT', [('name_text',1),('flag',1)],     'name'),
    0x6E: ('SET_NAME_VAR',   [('name_text',1),('flag',1)],     'name'),
    # --- 含文本的其他 op (UI/菜单/选择支) ---
    0x6C: ('OP_6C',          [('flag',4),('text',1)],          'msg_other'),
    0x7D: ('OP_7D',          [('flag',4),('text',1)],          'msg_other'),
    0x82: ('OP_82',          [('flag',2),('text',1)],          'msg_other'),
    0x93: ('OP_93',          [('flag',1),('text',1)],          'msg_other'),
    0x9C: ('OP_9C',          [('flag',4),('text',1)],          'msg_other'),
    0x9F: ('OP_9F',          [('flag',5),('text',1)],          'msg_other'),
    # --- 不含文本 ---
    0x02: ('WAIT',           [('flag',1)],                     'other'),
    0x03: ('DRAW_LINE',      [],                               'other'),
    0x04: ('DRAW_NORMAL',    [],                               'other'),
    0x05: ('DRAW_SAVE',      [],                               'other'),
    0x06: ('DRAW_CLEAR',     [],                               'other'),
    0x07: ('FLUSH',          [],                               'other'),
    0x0A: ('DIALOG',         [],                               'other'),
    0x0E: ('GET_MOUSE_X',    [],                               'other'),
    0x0F: ('GET_MOUSE_Y',    [],                               'other'),
    0x10: ('OP_10',          [('flag',1)],                     'other'),
    0x11: ('OP_11',          [],                               'other'),
    0x12: ('SCENE',          [('flag',1)],                     'other'),
    0x13: ('OP_13',          [],                               'other'),
    0x14: ('NOP',            [],                               'other'),
    0x15: ('IMG_2',          [('flag',2)],                     'other'),
    0x16: ('IMG_3',          [('flag',3)],                     'other'),
    0x5C: ('NOP5C',          [],                               'other'),
}

# ============================================================
# Header 解析
# ============================================================
def parse_header(data: bytes) -> dict:
    """解析 12 字节 header, 返回关键字段"""
    import struct
    index_slots = struct.unpack_from('<H', data, 4)[0] >> 1  # count*2 → count
    text_rel    = struct.unpack_from('<H', data, 6)[0]
    index_base  = 0x0C
    bc_base     = index_base + index_slots * 2
    text_base   = bc_base + text_rel
    return {
        'index_slots': index_slots,
        'text_rel':    text_rel,
        'index_base':  index_base,
        'bc_base':     bc_base,
        'text_base':   text_base,
        'bc_size':     text_rel,
    }

def parse_labels(data: bytes, hdr: dict) -> dict:
    """解析 label 表: {id: bc_offset}"""
    import struct
    labels = {}
    for i in range(0, hdr['index_slots'], 2):
        eid = struct.unpack_from('<H', data, hdr['index_base'] + i*2)[0]
        off = struct.unpack_from('<H', data, hdr['index_base'] + (i+1)*2)[0]
        if eid or off:
            labels[eid] = off
    return labels
