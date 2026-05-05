# juice/girl2

## 目录定位

面向 `girl2` 的工具目录，上级分类为 `juice`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `common.py` | 公共库/编解码 | GIRL2_95 XSD common template. 职责： 1. 批量路径遍历 2. XSD XOR FF + 解压 / mode0 输出 3. 0x10 文本块扫描 4. name / scr_msg / msg JSON 模板 5. 固定偏移截断注入基础逻辑 |
| `extract.py` | 提取/解析 | GIRL2_95 XSD 批量提取。 用法： python extract.py <XSD文件或目录> -o girl2_extract.json 输出统一 JSON： name 可选；没有角色名不输出 scr_msg 原始脚本文本，不改 msg 初始等于 scr_msg，只改这个字段 |
| `inject.py` | 注入/回写 | GIRL2_95 XSD 批量截断注入。 用法： python inject.py <XSD文件或目录> --json girl2_extract.json -o out_xsd 说明： - 只读取 JSON 里的 msg 字段回注。 - scr_msg 用于校验错位。 - 固定偏移截断，不做非等长重定位。 - 输出 XSD 使用 mode0 封装，未修改文 |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `scr_msg`, `msg`, `message`, `translation`。
- `scr_msg/src_msg` 一般表示原始脚本文本或原文定位依据，回写时不应随意修改。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `translation` 为空时部分注入器会回退到 `message/msg`，具体以脚本参数为准。

## 命令示例

### extract.py
```bash
python extract.py <XSD文件或目录> -o girl2_extract.json
```
### inject.py
```bash
python inject.py <XSD文件或目录> --json girl2_extract.json -o out_xsd
```

## 参数入口速查

### `extract.py`
- `"input", help="XSD 文件或目录，支持目录批量递归"`
- `"-o", "--output", default="girl2_extract.json", help="输出 JSON，默认 girl2_extract.json"`
- `"--ext", default=None, help="脚本扩展名。默认：普通模式 .XSD；--decoded 模式为全部文件；可填 .dec"`
- `"--encoding", default=DEFAULT_ENCODING, help="文本编码，默认 cp932"`
- `"--decoded", action="store_true", help="输入已经是解码后的 bytecode，不再做 XSD 解码"`
### `inject.py`
- `"input", help="XSD 文件或目录，支持目录批量递归"`
- `"--json", required=True, help="extract.py 输出并修改过 msg 的 JSON"`
- `"-o", "--output", required=True, help="输出文件或目录；输入目录时这里是输出目录"`
- `"--ext", default=None, help="脚本扩展名。默认：普通模式 .XSD；--decoded 模式为全部文件；可填 .dec"`
- `"--encoding", default=DEFAULT_ENCODING, help="注入编码，默认 cp932"`
- `"--errors", default="strict", choices=("strict", "replace", "ignore"`
- `"--allow-mismatch", action="store_true", help="scr_msg 不匹配时只警告不中止"`
- `"--decoded", action="store_true", help="输入/输出均为已解码 bytecode，不做 XSD 解码/封装"`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
