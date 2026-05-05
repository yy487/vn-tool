# AI5WIN/愛しの言霊

## 目录定位

面向 `愛しの言霊` 的工具目录，上级分类为 `AI5WIN`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `ai5v7_bytecode_v2.py` | 提取/解析 | ai5v7_bytecode_v2.py — V7 (Silky's 2001 "愛しの言霊") MES 字节码反汇编 + 重汇编 与 v1 的关键修正: 1. **MES 是 LZSS 压缩的** (旧版记忆里的"无压缩"是错的) - 标准 AI5 LZSS: 4KB 环形窗口 init=0xFEE, LSB-first flag, 12b off + 4 |
| `ai5winv7_arc_tool.py` | 封包/解包或格式工具 | ai5winv7_arc_tool.py — AI5WIN V7 (愛しの言霊 / シルキーズ 2001) ARC 封包工具 ARC 格式 (V7 独有, 与 V1-V6 全部不同): Header: u32 count // 条目数 Entry (28 字节): byte name[20] // 文件名, 每字节 ^ 0x03 u32 size ^ 0x5 |
| `ai5winv7_mes_extract.py` | 提取/解析 | ai5winv7_mes_extract.py — V7 (愛しの言霊) MES → GalTransl JSON 提取 流程: 1. LZSS 解压 (ai5v7_bytecode_v2.lzss_decompress) 2. 反汇编为指令流 (disassemble) 3. 识别 TEXT (op 0x01) 指令, 按 (NAME, NEW_LINE, |
| `ai5winv7_mes_inject.py` | 注入/回写 | ai5winv7_mes_inject.py — GalTransl JSON → V7 (愛しの言霊) MES 回注 流程: 1. 读 GalTransl JSON (translate 后的 name/message) 2. 读原 MES, 解压 + 反汇编得到指令流 3. 按 _meta.name_insn_idx / msg_insn_idx 用翻译 |
| `merge_json.py` | 提取/解析 | merge_json.py — 把旧版 (MENU_INIT bug 版反汇编器) 提取的翻译 JSON 与新版 (修复后) 提取的 JSON 合并. 背景: 旧版 ai5v7_bytecode_v2.py 把 MENU_INIT 的 u16 skip target 错误识别成 独立的 TEXT2/SJIS/JUMP 指令, 导致指令流里多出"幽灵指令",  |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### merge_json.py
```bash
python merge_json.py <orig_mes_dir> <old_json_dir> <new_out_dir>
```

## 参数入口速查

### `ai5winv7_mes_extract.py`
- `'mes_path'`
- `'json_out'`
- `'mes_dir'`
- `'json_dir'`
### `ai5winv7_mes_inject.py`
- `'orig_mes'`
- `'json'`
- `'out_mes'`
- `'orig_dir'`
- `'json_dir'`
- `'out_dir'`
- `'orig_mes'`
- `'json'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
