# fizz

## 目录定位

fizz 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `fizz_spt_cryptor.py` | 公共库/编解码 | Fizz ReVN::RxGSD::SPT Cryptor (独立模块 + CLI) 严格对齐 Core/SPT_Cryptor.cpp 算法: 文件头 4B = [start_index ^ 0xF0, decode_type ^ 0xF0, un0, un1] body (从 offset 4 开始): decrypt = decode_round0(t |
| `fizz_spt_extract.py` | 提取/解析 | Fizz SPT 对话提取器 (cmd=1 / Arg_Type0) 用法: fizz_spt_extract.py scan <in.spt> fizz_spt_extract.py extract <in.spt> <out.tl.json> fizz_spt_extract.py batch <spt_dir> <json_dir> ---- 引擎结构 |
| `fizz_spt_global.py` | 公共库/编解码 | Fizz SPT Global.dat reader (角色名字典) 用法 (CLI): fizz_spt_global.py info global.dat # 显示结构 fizz_spt_global.py names global.dat [out.json] # 输出 nameSeq→name 映射 库用法: from fizz_spt_global |
| `fizz_spt_inject.py` | 注入/回写 | Fizz SPT 注入器 (cmd=1 / Arg_Type0) 用法: # 1. 默认输出解密后的 .bin, 让 fizz_spt_cryptor 独立加密回 SPT (推荐) fizz_spt_extract.py extract fd.spt fd.tl.json # ... 翻译 fd.tl.json ... fizz_spt_inject.py  |
| `fizz_tool.py` | 封包/解包或格式工具 | fizz_tool.py - Fizz/l-soft .gsp archive unpack/repack Format (no compression, no encryption): u32 count count x { u32 offset ; absolute, from start of file u32 size char name[56] ; |

## 推荐流程

1. 如脚本存在加密/压缩层，先执行解密或解码步骤，再处理明文脚本。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `src_msg`, `message`。
- `scr_msg/src_msg` 一般表示原始脚本文本或原文定位依据，回写时不应随意修改。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### fizz_tool.py
```bash
python fizz_tool.py unpack  <archive.gsp> <out_dir>
python fizz_tool.py repack  <in_dir>      <archive.gsp>
python fizz_tool.py list    <archive.gsp>
```

## 参数入口速查

### `fizz_spt_cryptor.py`
- `'input'`
- `'output'`
- `'--readable', action='store_true', help='把头 2B 改成 FF FF (便于肉眼识别, 但丢失真参数!`
- `'input'`
- `'output'`
- `'--ref', help='参考 SPT 文件 (自动提取头参数`
- `'--start', type=lambda x: int(x, 0`
- `'--type', type=lambda x: int(x, 0`
- `'--un0', type=lambda x: int(x, 0`
- `'--un1', type=lambda x: int(x, 0`
- `'input'`
- `'input'`
### `fizz_spt_extract.py`
- `'input'`
- `'input'`
- `'output'`
- `'--global', dest='global_dat', help='global.dat 路径 (填充 name 字段`
- `'input_dir'`
- `'output_dir'`
- `'--global', dest='global_dat', help='global.dat 路径 (填充 name 字段`
### `fizz_spt_global.py`
- `'input'`
- `'input'`
- `'output', nargs='?'`
### `fizz_spt_inject.py`
- `'input_spt', help='源 SPT 文件 (或批量模式下的源 SPT 目录`
- `'input_json', help='翻译 JSON (或批量模式下的 JSON 目录`
- `'output', help='输出路径 (默认 .bin 需用 cryptor 加密; --encrypt 则输出 SPT`
- `'--varlen', action='store_true', help='变长重建 (sl0 可变`
- `'--encrypt', action='store_true', help='直接输出加密 SPT (用源 SPT 头参数`
- `'--enc', choices=['cp932', 'gbk'], default='cp932', help='字符编码 (默认 cp932 日文/日繁, gbk 用于简体中文`
- `'--gbk', action='store_true', help='(旧 alias`
- `'--batch', action='store_true', help='批量: 3 个参数解读为 spt_dir / json_dir / out_dir'`
### `fizz_tool.py`
- `'arc'`
- `'out_dir'`
- `'in_dir'`
- `'arc'`
- `'arc'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
