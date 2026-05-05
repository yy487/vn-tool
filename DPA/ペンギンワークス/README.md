# DPA/ペンギンワークス

## 目录定位

面向 `ペンギンワークス` 的工具目录，上级分类为 `DPA`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `dac_extract.py` | 提取/解析 | def split_speaker; def extract_file |
| `dac_inject.py` | 注入/回写 | def encode_cp932_safe; def inject_file |
| `dpk_tool.py` | 封包/解包或格式工具 | DAC 引擎 DPK 解包 / 封包工具 ============================= DPK (DAC Package) 是ペンギンワークス的 DAC 引擎所用的资源封包格式。 这个工具基于对 hentai.exe (へんたいイニシアチブ 2013) 的逆向 + 参考 GARbro (ArcDPK.cs) 源码完成。 文件结构 (全部 lit |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `file`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python dac_extract.py --help
```
```bash
python dac_inject.py --help
```
```bash
python dpk_tool.py --help
```

## 参数入口速查

### `dac_extract.py`
- `'input', help='.dac/.dacz 文件 或 目录'`
- `'-o', '--output', required=True, help='输出 JSON 路径 (单文件`
- `'--meta', help='元信息输出路径 (默认与 output 同目录`
### `dac_inject.py`
- `'input', help='原始 .dac/.dacz 文件 或 目录'`
- `'json', help='翻译 JSON 路径 或 目录'`
- `'-o', '--output', required=True, help='输出路径 (文件或目录`
- `'--meta', help='元信息路径 (默认 json + .meta.json`
- `'--verify', action='store_true', help='round-trip 校验: 注入后比对原文'`
### `dpk_tool.py`
- `'dpk', help='输入 .dpk 文件'`
- `'out', help='输出目录'`
- `'src', help='源目录 (含 _order.txt`
- `'dpk', help='输出 .dpk 文件'`
- `'dpk', help='输入 .dpk 文件'`
- `'dpk', help='输入 .dpk 文件'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
