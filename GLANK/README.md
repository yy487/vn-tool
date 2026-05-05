# GLANK

## 目录定位

GLANK 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `snr_extract_v2.py` | 提取/解析 | SNR 脚本文本提取工具 v2.1 — 字节码遍历, 支持 STSL + BTSL 用法: python snr_extract_v2.py BT_SNR.dat [ST_SNR.dat] -o snr_texts.json |
| `snr_inject_v2.py` | 注入/回写 | SNR 脚本文本注入工具 v2.1 — 字节码遍历 + 跳转修正, 支持 STSL + BTSL 用法: 提取: python snr_inject_v2.py BT_SNR.dat --extract-only -i out.json 注入: python snr_inject_v2.py BT_SNR.dat ST_SNR.dat -i translat |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `offset`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python snr_extract_v2.py --help
```
```bash
python snr_inject_v2.py --help
```

## 参数入口速查

### `snr_extract_v2.py`
- `'files',nargs='+'`
- `'-o','--output',default='snr_texts.json'`
### `snr_inject_v2.py`
- `'files',nargs='+'`
- `'-i','--input',required=True`
- `'-o','--outdir',default='output'`
- `'--extract-only',action='store_true'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
