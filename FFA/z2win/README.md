# FFA/z2win

## 目录定位

面向 `z2win` 的工具目录，上级分类为 `FFA`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `so4_extract.py` | 提取/解析 | Z2WIN SO4 文本提取工具 (FFA/G-SYS engine) v1.1, developed by natsuko 用法: 单文件: python so4_extract.py A0_000.SO4 单文件: python so4_extract.py A0_000.SO4 -o output.json 批量: python so4_extract |
| `so4_inject.py` | 注入/回写 | Z2WIN SO4 文本注入工具 (FFA/G-SYS engine) v1.1, developed by natsuko 用法: 安全模式(等长替换): python so4_inject.py A0_000.json A0_000.SO4 python so4_inject.py A0_000.json A0_000.SO4 -o patched.SO |
| `so4_lzss.py` | 公共库/编解码 | FFA 引擎 LZSS 压缩/解压工具 (纯 Python 实现) v1.0, developed by natsuko 替代 amanomiko_lzss.py (后者需要 liblzss20_64.dll) 用法: 解压单文件: python so4_lzss.py d A0_000.SO4 解压单文件: python so4_lzss.py d A0_ |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### so4_extract.py
```bash
python so4_extract.py A0_000.SO4                  # 单文件 → A0_000.json
python so4_extract.py A0_000.SO4 -o out.json      # 指定输出
python so4_extract.py ./decoded/ -o ./texts/       # 批量
python so4_extract.py A0_000.SO4 --all             # 含系统字符串""")
```
### so4_inject.py
```bash
python so4_inject.py A0_000.json A0_000.SO4
python so4_inject.py A0_000.json A0_000.SO4 -o patched.SO4
python so4_inject.py A0_000.json A0_000.SO4 --varlen
python so4_inject.py ./texts/ ./decoded/ -o ./patched/
python so4_inject.py ./texts/ ./decoded/ -o ./patched/ --varlen
python so4_inject.py A0_000.json A0_000.SO4
```
### so4_lzss.py
```bash
python so4_lzss.py d A0_000.SO4                   # 解压 → A0_000.SO4.dec
python so4_lzss.py d A0_000.SO4 -o decoded.bin     # 指定输出
python so4_lzss.py e A0_000.SO4.dec                # 压缩 → A0_000.SO4
python so4_lzss.py d ./so4_raw/ -o ./so4_dec/      # 批量解压
python so4_lzss.py e ./so4_dec/ -o ./so4_raw/      # 批量压缩""")
```

## 参数入口速查

### `so4_extract.py`
- `'input', help='SO4 文件或包含 SO4 的文件夹'`
- `'-o', '--output', default=None, help='输出 JSON 文件或文件夹 (默认: 同名 .json / out/`
- `'--encoding', default='cp932', help='文本编码 (默认 cp932`
- `'--all', action='store_true', help='导出全部字符串(含系统路径`
### `so4_inject.py`
- `'input', help='翻译 JSON 文件或 JSON 文件夹'`
- `'original', help='原始 SO4 文件或 SO4 文件夹'`
- `'-o', '--output', default=None, help='输出文件或文件夹 (默认: 原始文件名.patched`
- `'--encoding', default='cp932', help='目标编码 (默认 cp932`
- `'--varlen', action='store_true', help='变长替换模式 (默认: 等长安全模式`
### `so4_lzss.py`
- `'mode', choices=['d', 'e'], help='d=解压(decode`
- `'input', help='输入文件或文件夹'`
- `'-o', '--output', default=None, help='输出文件或文件夹'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
