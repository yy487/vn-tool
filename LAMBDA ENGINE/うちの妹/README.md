# LAMBDA ENGINE/うちの妹

## 目录定位

面向 `うちの妹` 的工具目录，上级分类为 `LAMBDA ENGINE`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `lax_tool.py` | 封包/解包或格式工具 | lax_tool.py -- Lapis LAX archive unpacker / repacker File format (confirmed against uchiimoj.exe): [+0x00] 8B "$LapH__\0" file signature [+0x08] ... data area (each file = concaten |
| `te_codec.py` | 公共库/编解码 | te_codec.py — Lapis ($TAMdatas) .te 文件结构 codec 提供底层的文件结构解析/构建能力，不涉及翻译语义。 extract 和 inject 工具共用此模块。 文件布局（已确认）： [0x00] $TAMdatas\0\0\0 12B magic [0x0C] u32 code_size [0x10] u32 text_ |
| `te_extract.py` | 提取/解析 | te_extract.py — 从 Lapis .te 文件提取剧情文本为 JSON 只处理剧情文件（@XXX label 数 >= MIN_LABELS_FOR_STORY），跳过系统/UI 文件。 JSON 格式（每条）: { "id": int, # 全局递增 "message": str, # 待翻译文本（翻译者只改这一项） "_label": st |
| `te_inject.py` | 注入/回写 | te_inject.py — 把翻译好的 JSON 写回 Lapis .te 文件（变长注入） 核心流程： 1. 收集所有替换点 (file_off, old_len, new_bytes) 2. 拼接新 text section 3. 建立 offset_map: 老 text 偏移 → 新 text 偏移 4. 用 map 修正 code 段和 tail |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`message`, `offset`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python lax_tool.py --help
```
```bash
python te_extract.py --help
```
```bash
python te_inject.py --help
```

## 参数入口速查

### `lax_tool.py`
- `"archive"`
- `"archive"`
- `"out_dir"`
- `"-d", "--decompress", action="store_true", help="also decompress each file's _AF chain into " "files_raw/ (usable for editing`
- `"in_dir"`
- `"archive"`
- `"--recompress", action="store_true", help="force recompression from files_raw/ even when " "raw size is unchanged (useful if you edited in " "place without changing length`
- `"in_path"`
- `"out_path"`
- `"in_path"`
- `"out_path"`
### `te_extract.py`
- `'input_dir'`
- `'output_dir'`
- `'--merge', action='store_true'`
### `te_inject.py`
- `'input_dir'`
- `'json_src'`
- `'output_dir'`
- `'-v', '--verbose', action='store_true'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
