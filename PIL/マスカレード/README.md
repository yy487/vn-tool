# PIL/マスカレード

## 目录定位

面向 `マスカレード` 的工具目录，上级分类为 `PIL`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `masq_common.py` | 公共库/编解码 | def read_u24be; def write_u24be; class HxpEntry; class HxpArchive |
| `masq_extract.py` | 提取/解析 | 源码未写模块说明，按函数和文件名判定用途。 |
| `masq_inject.py` | 注入/回写 | class Replacement; class OffsetMap; def find_script_start; def collect_string_ranges |
| `masq_pack.py` | 封包/解包或格式工具 | 源码未写模块说明，按函数和文件名判定用途。 |
| `masq_pipeline.py` | 辅助脚本 | def run |
| `masq_unpack.py` | 封包/解包或格式工具 | 源码未写模块说明，按函数和文件名判定用途。 |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `msg`, `message`, `file`, `offset`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python masq_extract.py --help
```
```bash
python masq_inject.py --help
```
```bash
python masq_pack.py --help
```
```bash
python masq_pipeline.py --help
```
```bash
python masq_unpack.py --help
```

## 参数入口速查

### `masq_extract.py`
- `"unpacked_dir", type=Path`
- `"-o", "--output", type=Path, required=True, help="output text-json directory"`
- `"--encoding", default="cp932"`
- `"--min-chars", type=int, default=1`
### `masq_inject.py`
- `"unpacked_dir", type=Path`
- `"texts_dir", type=Path`
- `"-o", "--output", type=Path, required=True, help="patched unpacked directory"`
- `"--encoding", default="cp932"`
- `"--errors", default="strict", choices=["strict", "replace", "ignore"]`
- `"--generic-u24", action="store_true", help="also scan and relocate generic u24-looking script targets; off by default"`
- `"--report", type=Path`
### `masq_pack.py`
- `"patched_dir", type=Path`
- `"-o", "--output", type=Path, required=True`
### `masq_pipeline.py`
- `"input_hxp", type=Path`
- `"texts_dir", type=Path`
- `"-o", "--output", type=Path, required=True`
- `"--workdir", type=Path, default=Path("_masq_build"`
- `"--encoding", default="cp932"`
- `"--generic-u24", action="store_true"`
### `masq_unpack.py`
- `"input_hxp", type=Path`
- `"-o", "--output", type=Path, required=True`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
