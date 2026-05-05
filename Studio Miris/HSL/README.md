# Studio Miris/HSL

## 目录定位

面向 `HSL` 的工具目录，上级分类为 `Studio Miris`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `hmo_extract.py` | 提取/解析 | HMO 消息文本提取工具 (インタールード / Interlude 引擎) 格式: msg.dat (magic='HMO ', XOR 0xFF 加密) 用法: python hmo_extract.py msg.dat -o msg_texts.json HMO 文件格式 (来自 exe FUN_00413cb0): 0 magic (4) = 'HMO |
| `hmo_inject.py` | 注入/回写 | HMO 消息文本注入工具 (インタールード / Interlude 引擎) 格式: msg.dat (magic='HMO ', XOR 0xFF 加密) 用法: python hmo_inject.py msg.dat -i msg_texts.json -o output/ 注入流程: 1. 按原样读取所有 entry (解密后字节) 2. 对 JSON |
| `hsl_extract.py` | 提取/解析 | hsl_extract.py - HSL 脚本引擎选项提取工具 (字节扫描方案) 目标: hadaka/HSL snr.dat 里的 211 个选项 (opcode 0x111) 方案: 1. 解析 HSL header 拿到 275 个 block 的文件偏移 2. 在每个 block body 里线性扫描 `11 01` 字节模式 3. 对每个命中做 s |
| `hsl_inject.py` | 注入/回写 | hsl_inject.py - HSL 脚本引擎选项变长注入工具 核心工作流: 1. 读取翻译 JSON (GalTransl 格式, 含 _block_idx / _body_pc / _orig_str_len) 2. 按 block 分组注入, 每个 block 内从后往前替换 (避免 body_pc 失效) 3. 变长替换产生 delta, 修正:  |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `voice`, `target`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python hmo_extract.py --help
```
```bash
python hmo_inject.py --help
```
```bash
python hsl_extract.py --help
```
```bash
python hsl_inject.py --help
```

## 参数入口速查

### `hmo_extract.py`
- `'files', nargs='+'`
- `'-o', '--output', default='msg_texts.json'`
### `hmo_inject.py`
- `'files', nargs='+'`
- `'-i', '--input', required=True, help='翻译 JSON'`
- `'-o', '--outdir', default='output'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
