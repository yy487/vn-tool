# MAI

## 目录定位

MAI 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `sct_extract.py` | 提取/解析 | sct_extract.py - MSC/SCT 脚本文本提取工具 引擎: NikuyokuH (MSC格式, HS engine) 输出: GalTransl兼容JSON (name/message/id) 用法: python sct_extract.py <input.sct> [output.json] |
| `sct_inject (8).py` | 注入/回写 | sct_inject.py - MSC/SCT 脚本文本注入工具 (v5) 引擎: NikuyokuH (MSC格式, HS engine) 批量模式: 同时处理 main.sct + scene.sct + at 文件 等长(默认): ##后0x20填充，不改偏移 变长(--varlen): 5层完整修正 ① SCT场景表 offset/size ② at |
| `sct_inject.py` | 注入/回写 | sct_inject.py - MSC/SCT 脚本文本注入工具 (v5) 引擎: NikuyokuH (MSC格式, HS engine) 批量模式: 同时处理 main.sct + scene.sct + at 文件 等长(默认): ##后0x20填充，不改偏移 变长(--varlen): 5层完整修正 ① SCT场景表 offset/size ② at |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `translation`, `index`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `translation` 为空时部分注入器会回退到 `message/msg`，具体以脚本参数为准。

## 命令示例

### sct_inject (8).py
```bash
python sct_inject.py --main <orig_main.sct> <main.json> --scene <orig_scene.sct> <scene.json> --at <at_file> [--outdir DIR] [--encoding ENC] [--varlen]
python sct_inject.py <orig.sct> <trans.json> [out.sct] [--at <at>] [--encoding ENC] [--varlen]
```
### sct_inject.py
```bash
python sct_inject.py --main <orig_main.sct> <main.json> --scene <orig_scene.sct> <scene.json> --at <at_file> [--outdir DIR] [--encoding ENC] [--varlen]
python sct_inject.py <orig.sct> <trans.json> [out.sct] [--at <at>] [--encoding ENC] [--varlen]
```

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
