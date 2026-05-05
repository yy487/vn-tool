# FFA/chuchu

## 目录定位

面向 `chuchu` 的工具目录，上级分类为 `FFA`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `x2win_so4_extract.py` | 提取/解析 | X2WIN SO4 文本提取工具 (FFA/G-SYS engine, 天巫女姫) v1.0, developed by natsuko 用法: 单文件: python x2win_so4_extract.py A0_000.SO4 单文件: python x2win_so4_extract.py A0_000.SO4 -o output.json 批量:  |
| `x2win_so4_inject.py` | 注入/回写 | X2WIN SO4 文本注入工具 (FFA/G-SYS engine, 天巫女姫) v1.0, developed by natsuko 用法: 等长模式(安全): python x2win_so4_inject.py trans.json orig.SO4 python x2win_so4_inject.py trans.json orig.SO4 -o  |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### x2win_so4_extract.py
```bash
python x2win_so4_extract.py x2_a0.SO4                 # → x2_a0.json
python x2win_so4_extract.py x2_a0.SO4 -o out.json     # 指定输出
python x2win_so4_extract.py ./decoded/ -o ./texts/     # 批量""")
```
### x2win_so4_inject.py
```bash
python x2win_so4_inject.py trans.json orig.SO4
python x2win_so4_inject.py trans.json orig.SO4 -o patched.SO4
python x2win_so4_inject.py trans.json orig.SO4 --varlen
python x2win_so4_inject.py ./texts/ ./decoded/ -o ./patched/
python x2win_so4_inject.py ./texts/ ./decoded/ -o ./patched/ --varlen
python x2win_so4_inject.py trans.json orig.SO4             # 等长安全模式
```

## 参数入口速查

### `x2win_so4_extract.py`
- `'input', help='SO4 文件或文件夹'`
- `'-o', '--output', default=None, help='输出 JSON 或文件夹'`
### `x2win_so4_inject.py`
- `'input', help='翻译 JSON 或 JSON 文件夹'`
- `'original', help='原始 SO4 或 SO4 文件夹'`
- `'-o', '--output', default=None, help='输出文件/夹'`
- `'--encoding', default='cp932', help='目标编码 (默认 cp932`
- `'--varlen', action='store_true', help='变长替换模式'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
