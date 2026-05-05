# FVP/クラ☆クラ CLASSY☆CRANBERRY’S

## 目录定位

面向 `クラ☆クラ CLASSY☆CRANBERRY’S` 的工具目录，上级分类为 `FVP`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `hcb_extract.py` | 提取/解析 | hcb_extract.py — HCB脚本文本提取工具 引擎: アトリエかぐや/ωstar HCB字节码 (v26) 游戏: BOIN, クラ☆クラ CLASSY☆CRANBERRY'S 等 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 用法 ━━━━━━━━━━━━━━━━━━━━ |
| `hcb_inject.py` | 注入/回写 | hcb_inject.py — HCB脚本文本注入工具 引擎: アトリエかぐや/ωstar HCB字节码 (v26) 游戏: BOIN, クラ☆クラ CLASSY☆CRANBERRY'S 等 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 用法 ━━━━━━━━━━━━━━━━━━━━━ |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `translation`, `offset`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `translation` 为空时部分注入器会回退到 `message/msg`，具体以脚本参数为准。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

### hcb_extract.py
```bash
python hcb_extract.py s.hcb
python hcb_extract.py s.hcb -o s.json
python hcb_extract.py s.hcb -f txt
python hcb_extract.py s.hcb --info
python hcb_extract.py s.hcb                  提取为JSON
python hcb_extract.py s.hcb -o out.json      指定输出路径
```
### hcb_inject.py
```bash
python hcb_inject.py 原始.hcb 翻译.json
python hcb_inject.py 原始.hcb 翻译.json -o 输出.hcb
python hcb_inject.py 原始.hcb 翻译.txt -o 输出.hcb
python hcb_inject.py 原始.hcb 翻译.json -e cp932
python hcb_extract.py 留档\\s.hcb -o s.json
python hcb_inject.py 留档\\s.hcb s_translated.json -o s.hcb
```

## 参数入口速查

### `hcb_extract.py`
- `'input', help='输入HCB文件路径'`
- `'-o', '--output', help='输出文件路径 (默认: 同名.json/.txt`
- `'-f', '--format', choices=['json', 'txt'], default='json', help='输出格式: json(默认`
- `'--info', action='store_true', help='仅显示文件信息,不提取文本'`
### `hcb_inject.py`
- `'input', help='原始HCB文件路径 (必须是未修改过的原版`
- `'translation', help='翻译文件路径 (.json 或 .txt`
- `'-o', '--output', help='输出HCB文件路径 (默认: 原文件名_cn.hcb`
- `'-e', '--encoding', default='cp932', help='目标编码 (默认: cp932`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
