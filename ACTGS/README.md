# ACTGS

## 目录定位

ACTGS 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `scr_crypto.py` | 公共库/编解码 | ACTGS 引擎 - 加解密与档案处理核心模块 被 scr_extract.py 和 scr_inject.py 共用 提供: - auto_find_key(exe_path) 从 ACTGS.exe 自动搜索 XOR 密钥 - xor_cycle(data, key) 循环 XOR (索引从 1 开始) - decrypt_script(raw, key |
| `scr_extract.py` | 提取/解析 | ACTGS 引擎 .scr 脚本文本提取工具 从 arc.scr 档案中提取可翻译文本为 GalTransl 兼容 JSON 用法: python scr_extract.py <ACTGS.exe> <arc.scr> [输出目录] |
| `scr_inject.py` | 注入/回写 | ACTGS 引擎 .scr 脚本文本注入工具 将翻译 JSON 注入回 arc.scr 用法: python scr_inject.py <ACTGS.exe> <arc.scr> <翻译JSON目录> [输出arc.scr] [编码] 编码默认 cp932，汉化用 gbk |

## 推荐流程

1. 如脚本存在加密/压缩层，先执行解密或解码步骤，再处理明文脚本。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python scr_extract.py --help
```
```bash
python scr_inject.py --help
```

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
