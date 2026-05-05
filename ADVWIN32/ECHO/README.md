# ADVWIN32/ECHO

## 目录定位

面向 `ECHO` 的工具目录，上级分类为 `ADVWIN32`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `mes_extract.py` | 提取/解析 | mes_extract.py - ADVWIN32 MES script text extractor Engine: ADVWIN32 (F&C Co., Ltd.) Usage: python mes_extract.py <unpacked_dir> -o texts.json Only extracts from numeric-named MES  |
| `mes_inject.py` | 注入/回写 | mes_inject.py - ADVWIN32 MES script text injector Engine: ADVWIN32 (F&C Co., Ltd.) Usage: python mes_inject.py <orig_unpacked_dir> <texts.json> -o <patched_dir> Injects translated  |
| `mrg_tool.py` | 封包/解包或格式工具 | mrg_tool.py - F&C Co. MRG archive unpack/repack tool Engine: ADVWIN32 (F&C Co., Ltd.) Format: MRG v1 (index encrypted with ROL1+XOR stream cipher, data LZSS compressed) Usage: pyth |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `offset`, `index`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

### mes_extract.py
```bash
python mes_extract.py <unpacked_dir> -o texts.json
```
### mes_inject.py
```bash
python mes_inject.py <orig_unpacked_dir> <texts.json> -o <patched_dir>
```
### mrg_tool.py
```bash
python mrg_tool.py unpack  ECHO_MES.MRG -o output_dir/
python mrg_tool.py repack  output_dir/ -o ECHO_MES_NEW.MRG
python mrg_tool.py list    ECHO_MES.MRG
```

## 参数入口速查

### `mes_extract.py`
- `'input', help='Unpacked MES directory'`
- `'-o', '--output', default='texts.json', help='Output JSON file'`
### `mes_inject.py`
- `'orig_dir', help='Original unpacked MES directory'`
- `'texts', help='Translated texts JSON file'`
- `'-o', '--output', required=True, help='Output patched directory'`
### `mrg_tool.py`
- `'input'`
- `'-o', '--output'`
- `'input'`
- `'-o', '--output'`
- `'input'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
