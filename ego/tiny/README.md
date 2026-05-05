# ego/tiny

## 目录定位

面向 `tiny` 的工具目录，上级分类为 `ego`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `bsf1_codec.py` | 公共库/编解码 | bsf1_codec.py — Studio e.go! / TwinWay BSF1 脚本反汇编底层模块 基于 tw.exe 逆向: FUN_00413021 标签查找 (定位 label table 结构) FUN_00413106 VM 主循环 (39 outer opcode + 18 group0 sub_op 消费规则) FUN_00416168 |
| `dat_tool.py` | 封包/解包或格式工具 | dat_tool.py — Studio e.go! 引擎 DAT 归档 (DAT/EGO/0, OldDat 变体) 解包/封包工具 格式: u32 index_size ; 不含自身, data_offset = 4 + index_size entries[]: ; 每条变长, 紧密排列至 data_offset u32 entry_len ; 包含自 |
| `scr_extract.py` | 提取/解析 | scr_extract.py — Studio e.go!/TwinWay BSF1 脚本文本提取器 从 .scr 里抽出 CP932 台词 (混在 opcode 流里的裸 cstring), 附带前置 SPEAKER 指令指定的说话人, 输出 GalTransl 风格 JSON: [ {"id": 0, "pc": "0x578", "name": "僚" |
| `scr_inject.py` | 注入/回写 | scr_inject.py — Studio e.go!/TwinWay BSF1 脚本文本变长注入器 把 scr_extract 产出的 JSON 翻译写回 .scr, 支持变长 (译文长度 ≠ 原文)。 变长注入核心逻辑: 1. 完整反汇编原 scr, 得到 (labels, insns) 2. 逐条指令重新打包, 文本条目换成翻译后的 CP932 字节 |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `raw`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### dat_tool.py
```bash
python dat_tool.py list    game00.dat
python dat_tool.py unpack  game00.dat  out_dir/
python dat_tool.py pack    out_dir/    game00_new.dat
python dat_tool.py verify  game00.dat  game00_new.dat
```
### scr_extract.py
```bash
python scr_extract.py extract Daytalk.scr daytalk.json
python scr_extract.py batch   indir/       outdir/
python scr_extract.py disasm  Daytalk.scr               # 人读反汇编
```
### scr_inject.py
```bash
python scr_inject.py inject Daytalk.scr daytalk.json Daytalk_new.scr
python scr_inject.py verify original.scr rebuilt.scr
python scr_inject.py batch  origdir/ jsondir/ outdir/
```

## 参数入口速查

### `dat_tool.py`
- `'archive'`
- `'archive'`
- `'outdir'`
- `'indir'`
- `'archive'`
- `'archive1'`
- `'archive2'`
### `scr_extract.py`
- `'scr'`
- `'out'`
- `'indir'`
- `'outdir'`
- `'scr'`
### `scr_inject.py`
- `'scr'`
- `'json'`
- `'out'`
- `'scrdir'`
- `'jsondir'`
- `'outdir'`
- `'a'`
- `'b'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
