# AI5WIN/らいむいろ流奇譚X cross～恋、教ヘテクダサイ。～

## 目录定位

面向 `らいむいろ流奇譚X cross～恋、教ヘテクダサイ。～` 的工具目录，上级分类为 `AI5WIN`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `arc_tool.py` | 封包/解包或格式工具 | Line2 Engine ARC Archive Tool (通用版) ======================================= 目标引擎: Line2 系列 (ライン2等多款游戏通用) 封包格式: .arc (Mes.Arc / Data.Arc / Bg.Arc / Music.Arc / Effect.Arc / Voice.Ar |
| `mes_extract.py` | 提取/解析 | Line2 Engine MES Script Text Extractor ======================================= 用法: python mes_extract.py <input.mes> [output.json] MES格式: 整个文件LZSS压缩。解压后: - 字节码VM，文本以 01 + CP932字符串  |
| `mes_inject.py` | 注入/回写 | AI5WIN (Line2) Engine MES Script Text Injector ================================================ 用法: python mes_inject.py <original.mes> <translated.json> [output.mes] python mes_in |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `offset`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

### arc_tool.py
```bash
python arc_tool.py unpack <archive.arc> [output_dir] [--exe game.exe]
python arc_tool.py pack   <input_dir> <output.arc>  [--exe game.exe]
python arc_tool.py list   <archive.arc>              [--exe game.exe]
python arc_tool.py scan   <game.exe>                 (扫描EXE中的密钥)
```
### mes_inject.py
```bash
python mes_inject.py <mes_dir> <json_dir> <output_dir>  (batch mode)
```

## 参数入口速查

### `arc_tool.py`
- `'exe_path', help='游戏EXE路径'`
- `'arc_path'`
- `'--exe', help='游戏EXE (自动提取密钥`
- `'--keys', help='手动密钥: byte,size,offset'`
- `'arc_path'`
- `'output', nargs='?', help='输出目录'`
- `'--exe', help='游戏EXE (自动提取密钥`
- `'--keys', help='手动密钥: byte,size,offset'`
- `'input_dir'`
- `'arc_path'`
- `'--exe', help='游戏EXE (自动提取密钥`
- `'--keys', help='手动密钥: byte,size,offset'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
