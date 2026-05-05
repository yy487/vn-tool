# ail

## 目录定位

ail 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `ail_extract.py` | 提取/解析 | Generic AILSystem JSON text extractor. Output keeps the old project JSON shape: id / pc / sub / kind / text_off / [name fields] / message / src_msg |
| `ail_inject.py` | 注入/回写 | Generic AILSystem JSON text injector. Supports three injection modes: fixed - overwrite original slots, truncate overflow, keep offsets unchanged append - append changed strings an |
| `ail_opcode_tables.py` | 公共库/编解码 | AIL function opcode tables ported from AIL_Tools Script.cs. Each sub opcode maps to a tuple of field actions: expr: consume one AIL expression text: consume one u16 string-pool off |
| `ail_script_core.py` | 辅助脚本 | Generic AILSystem script parser used by JSON extract/inject tools. The parser keeps the old BONDAGE JSON workflow, but uses AIL_Tools-style function opcode tables and expression co |
| `bondage_extract.py` | 提取/解析 | Compatibility wrapper for BONDAGE-style extraction. The real generic implementation is ail_extract.py. This wrapper keeps the old entry-point name and defaults to --profile bondage |
| `bondage_inject.py` | 注入/回写 | Compatibility wrapper for BONDAGE-style injection. The real generic implementation is ail_inject.py. Defaults stay CP932, version=2, profile=bondage. |
| `snl_tool.py` | 封包/解包或格式工具 | snl_tool.py v2 - AIL 引擎 .snl / .dat 容器格式工具 适用厂商: アイル (AIL / ail-soft.com) 样本文件: sall.snl / GALL*.DAT / PALL*.DAT / VALL*.DAT / THELP.DAT =========================================== |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `src_msg`, `msg`, `message`, `translation`, `type`, `end`, `encoding`, `raw`。
- `scr_msg/src_msg` 一般表示原始脚本文本或原文定位依据，回写时不应随意修改。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `translation` 为空时部分注入器会回退到 `message/msg`，具体以脚本参数为准。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python ail_extract.py --help
```
```bash
python ail_inject.py --help
```
```bash
python bondage_extract.py --help
```
```bash
python bondage_inject.py --help
```
```bash
python snl_tool.py --help
```

## 参数入口速查

### `ail_extract.py`
- `'input', help='decompressed AIL script .bin'`
- `'out_dir', nargs='?', default='.', help='output directory'`
- `'--version', type=int, default=2, choices=[0, 1, 2], help='AIL function table version; default: 2'`
- `'--encoding', default='cp932', help='string encoding; default: cp932'`
- `'--profile', default='generic', choices=['generic', 'bondage'], help='semantic profile; default: generic'`
- `'--scan', default='both', choices=['labels', 'linear', 'both'], help='scan strategy; default: both'`
- `'--resync', action='store_true', help='try byte-by-byte resync after parse errors; may create false positives'`
### `ail_inject.py`
- `'bin_path'`
- `'bin_path'`
- `'json_path'`
- `'out_bin'`
- `'--version', type=int, default=2, choices=[0, 1, 2]`
- `'--encoding', default='cp932'`
- `'--profile', default='generic', choices=['generic', 'bondage']`
- `'--scan', default='both', choices=['labels', 'linear', 'both']`
- `'--resync', action='store_true'`
- `'--mode', default='varlen', choices=['varlen', 'fixed', 'append']`
- `'--fixed', action='store_true', help='compat alias for --mode fixed'`
- `'--append', action='store_true', help='compat alias for --mode append'`
### `bondage_extract.py`
- `'input'`
- `'out_dir', nargs='?', default='.'`
- `'--scan', default='both', choices=['labels', 'linear', 'both']`
- `'--resync', action='store_true'`
### `bondage_inject.py`
- `'bin_path'`
- `'bin_path'`
- `'json_path'`
- `'out_bin'`
- `'--mode', default='varlen', choices=['varlen', 'fixed', 'append']`
- `'--fixed', action='store_true'`
- `'--append', action='store_true'`
- `'--names'`
- `'--errors', default='replace', choices=['strict', 'replace', 'ignore']`
- `'--map'`
### `snl_tool.py`
- `'snl'`
- `'-o', '--out', default='snl_out'`
- `'--raw', action='store_true', help='保留原始压缩态'`
- `'dir'`
- `'-o', '--out', default='sall_new.snl'`
- `'snl'`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`ail_lzss`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
