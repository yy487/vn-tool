# silky

## 目录定位

silky 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `silky_extract.py` | 提取/解析 | silky_extract.py — Silky MES op.txt -> translate.txt 文本提取。 输入：silky_op.py 生成的 *.op.txt 输出：translate.txt（GalTransl 风格的双行格式 ◇/◆，◇ 行原文，◆ 行待翻译） 设计： * 不做注音特殊解析。每个对话块里所有 STR_CRYPT (0x0A) |
| `silky_inject.py` | 注入/回写 | silky_inject.py — Silky MES translate.txt + op.txt -> 新 op.txt 译文注入。 输入： - 原始 *.op.txt（silky_op disasm 产物） - translate.txt（译者修改过的 ◆ 行） 输出： - 新的 *.op.txt（◆ 行的译文已替换到对应 STR_CRYPT/STR_ |
| `silky_op.py` | 公共库/编解码 | silky_op.py — Silky engine MES script <-> opcode txt 双向转换。 负责字节级双向转换： disassemble: *.MES (二进制脚本) -> *.op.txt (人类可读 opcode 流) assemble: *.op.txt -> *.MES OP 表、STR_CRYPT 压缩/解压、跳转偏移修复 |
| `silky_pipeline.py` | 注入/回写 | silky_pipeline.py — Silky MES 一站式批量处理（多进程并行）。 把 4 步流水线合成 2 个命令： unpack: *.MES -> op.txt + translate.txt (反汇编 + 提取) pack: op.txt + translate.txt -> *.MES (注入 + 汇编) 每个 .MES 独立处理，自动用所 |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`。

## 命令示例

### silky_extract.py
```bash
python silky_extract.py <input.op.txt> <output.translate.txt>
```
### silky_inject.py
```bash
python silky_inject.py <orig.op.txt> <translate.txt> <new.op.txt>
```
### silky_op.py
```bash
python silky_op.py disasm <in.MES> <out.op.txt> [--encoding cp932]
python silky_op.py asm    <in.op.txt> <out.MES> [--encoding cp932]
```
### silky_pipeline.py
```bash
python silky_pipeline.py unpack <MES目录> <工作目录> [-j N]
python silky_pipeline.py pack <MES目录> <工作目录> <输出目录> [-j N]
```

## 参数入口速查

### `silky_extract.py`
- `"input", help="单个 *.op.txt 文件，或包含 *.op.txt 的目录"`
- `"output", help="单文件输出路径，或输出目录"`
- `"--pattern", default="*.op.txt", help="目录模式下的 glob 通配符 (default: *.op.txt`
### `silky_inject.py`
- `"op_txt", help="原始 *.op.txt (单文件 或 目录`
- `"translate_txt", help="译文 translate.txt (单文件 或 目录`
- `"output_op_txt", help="新 op.txt (单文件 或 输出目录`
- `"--pattern", default="*.op.txt", help="目录模式下匹配 op.txt 的通配 (default: *.op.txt`
### `silky_op.py`
- `"input", help="单个 .MES 文件，或包含 .MES 的目录"`
- `"output", help="单文件输出路径，或目录"`
- `"--encoding", default="cp932"`
- `"--verbose", action="store_true"`
- `"--pattern", default="*.MES", help="目录模式下的 glob 通配符 (default: *.MES`
- `"input", help="单个 op.txt 文件，或包含 op.txt 的目录"`
- `"output", help="单文件输出路径，或目录"`
- `"--encoding", default="cp932"`
- `"--verbose", action="store_true"`
- `"--pattern", default="*.op.txt", help="目录模式下的 glob 通配符 (default: *.op.txt`
### `silky_pipeline.py`
- `"mes_dir"`
- `"workdir"`
- `"--encoding", default="cp932"`
- `"-j", "--jobs", type=int, default=0, help="并行进程数 (默认 CPU 核数 - 1, 1 = 单进程`
- `"mes_dir", help="（占位）"`
- `"workdir"`
- `"output_dir"`
- `"--encoding", default="cp932"`
- `"-j", "--jobs", type=int, default=0, help="并行进程数 (默认 CPU 核数 - 1, 1 = 单进程`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`concurrent`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
