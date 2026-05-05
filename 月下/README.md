# 月下

## 目录定位

月下 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `ssb_text.py` | 辅助脚本 | 月下の契り (Tsuki no Chigiri) SSB Script Text Tool Engine: SAISYS (栈式VM, CODE.SSB + DATA.SSB) Usage: python ssb_text.py extract CODE.SSB DATA.SSB [-o output.json] python ssb_text.py inj |

## 推荐流程

1. 按脚本文件名区分入口：extract 负责导出，inject 负责回写，*_tool/codec/common 作为格式工具或公共库。

## 命令示例

### ssb_text.py
```bash
python ssb_text.py extract CODE.SSB DATA.SSB [-o output.json]
python ssb_text.py inject  CODE.SSB DATA.SSB input.json [-o out_dir] [-e gbk]
```

## 参数入口速查

### `ssb_text.py`
- `'code', help='CODE.SSB path'`
- `'data', help='DATA.SSB path'`
- `'-o', '--output', default='ssb_text.json', help='Output JSON (default: ssb_text.json`
- `'code', help='CODE.SSB path'`
- `'data', help='DATA.SSB path'`
- `'json', help='Translated JSON path'`
- `'-o', '--output', default='output', help='Output directory (default: output`
- `'-e', '--encoding', default='cp932', help='Write encoding (default: cp932, use gbk for Chinese`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
