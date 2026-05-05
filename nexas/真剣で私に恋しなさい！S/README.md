# nexas/真剣で私に恋しなさい！S

## 目录定位

面向 `真剣で私に恋しなさい！S` 的工具目录，上级分类为 `nexas`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `nexas_common.py` | 公共库/编解码 | nexas_common.py - NeXAS / 真剣演舞 引擎脚本通用解析模块 文件格式（融合开源工具的语义理解 + 自家结构分析）: [u32 magic] = 0x11D3 (剧本) / 0x11E7 (system.bin) 同时也作为 extras_count [extras magic × (u32 op, u32 arg)] 开源工具叫 EX |
| `nexas_disasm.py` | 提取/解析 | nexas_disasm.py - NeXAS / 真剣演舞 引擎脚本批量反汇编器 用法: python nexas_disasm.py <input_dir> # 默认输出到 <input_dir>_disasm python nexas_disasm.py <input_dir> -o <output_dir> python nexas_disasm.p |
| `nexas_extract.py` | 提取/解析 | nexas_extract.py - NeXAS 脚本批量文本提取 (GalTransl 兼容格式) 把每个 .bin 中的对话和选项提取为 GalTransl/SExtractor 标准格式的 JSON。 用法: python nexas_extract.py <input_dir> # 默认 -> <input_dir>_json/ python nex |
| `nexas_inject.py` | 注入/回写 | nexas_inject.py - NeXAS 脚本批量文本注入 读原始 .bin + 翻译后的 .json (GalTransl 格式)，输出注入后的新 .bin。 用法: python nexas_inject.py <bin_dir> --json <json_dir> -o <output_dir> python nexas_inject.py me |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `file`, `end`, `voice`, `choices`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

### nexas_disasm.py
```bash
python nexas_disasm.py <input_dir>                 # 默认输出到 <input_dir>_disasm
python nexas_disasm.py <input_dir> -o <output_dir>
python nexas_disasm.py <input_dir> --no-extras     # 跳过 extras 区
python nexas_disasm.py <input_dir> --summary-only  # 只生成 _summary.csv
python nexas_disasm.py mes/                          # 默认 -> mes_disasm/
python nexas_disasm.py mes/ -o disasm/
```
### nexas_extract.py
```bash
python nexas_extract.py <input_dir>                  # 默认 -> <input_dir>_json/
python nexas_extract.py <input_dir> -o text_jp/
```
### nexas_inject.py
```bash
python nexas_inject.py <bin_dir> --json <json_dir> -o <output_dir>
python nexas_inject.py mes/ --json text_zh/ -o mes_zh/ --encoding gbk
python nexas_inject.py mes\\ --json text_zh\\ -o mes_zh\\ --encoding gbk
python nexas_extract.py mes\\ -o /tmp/jp\\
python nexas_inject.py mes\\ --json /tmp/jp\\ -o /tmp/rebuilt\\
```

## 参数入口速查

### `nexas_disasm.py`
- `'input_dir', help='含 .bin 脚本的目录'`
- `'-o', '--output', default=None, help='输出目录'`
- `'--no-extras', action='store_true', help='跳过 extras 区'`
- `'--no-strings', action='store_true', help='跳过字符串列表区'`
- `'--pattern', default='*.bin', help='文件匹配模式'`
- `'--no-summary', action='store_true', help='不生成 _summary.csv'`
- `'--summary-only', action='store_true', help='只生成 _summary.csv'`
### `nexas_extract.py`
- `'input_dir', help='含 .bin 的目录'`
- `'-o', '--output', default=None, help='输出 .json 目录'`
- `'--pattern', default='*.bin'`
### `nexas_inject.py`
- `'bin_dir', help='原始 .bin 目录'`
- `'--json', dest='json_dir', required=True, help='翻译后 .json 目录'`
- `'-o', '--output', required=True, help='输出 .bin 目录'`
- `'--encoding', default='cp932', choices=['cp932', 'gbk'], help='字符串编码 (默认 cp932,中文用 gbk`
- `'--pattern', default='*.bin'`
- `'--strict', action='store_true', help='缺少 .json 时报错 (默认跳过`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
