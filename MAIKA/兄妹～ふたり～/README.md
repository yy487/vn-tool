# MAIKA/兄妹～ふたり～

## 目录定位

面向 `兄妹～ふたり～` 的工具目录，上级分类为 `MAIKA`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `akb_extract.py` | 提取/解析 | def extract_file |
| `akb_inject.py` | 注入/回写 | def choose_text; def build_replacement_for_item; def inject_file |
| `akb_op.py` | 公共库/编解码 | AKB/ADB script common opcode template and binary helpers. Target format observed in TWO.EXE scripts: - little-endian uint16 opcode - most resource/text operands are CP932 C strings |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `msg`, `message`, `translation`, `type`, `file`, `offset`, `line_id`, `ctrl`, `voice`, `choice`, `target`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `translation` 为空时部分注入器会回退到 `message/msg`，具体以脚本参数为准。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python akb_extract.py --help
```
```bash
python akb_inject.py --help
```

## 参数入口速查

### `akb_extract.py`
- `"input", help="ADB file or directory containing ADB files"`
- `"-o", "--output", default="akb_text.json", help="output JSON path"`
- `"--encoding", default=DEFAULT_ENCODING, help="script string encoding, default cp932"`
- `"--strict", action="store_true", help="fail on unknown opcodes instead of resyncing"`
### `akb_inject.py`
- `"input", help="source ADB file or directory"`
- `"json", help="JSON produced by akb_extract.py"`
- `"-o", "--output", required=True, help="output ADB file or directory"`
- `"--encoding", default=DEFAULT_ENCODING, help="script string encoding, default cp932"`
- `"--errors", default="strict", choices=["strict", "replace", "ignore"], help="encoding error mode"`
- `"--use-message", action="store_true", help="inject item.message when translation is empty; useful after overwriting message in JSON"`
- `"--loose", action="store_true", help="recover from unknown opcodes; not recommended for final build"`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
