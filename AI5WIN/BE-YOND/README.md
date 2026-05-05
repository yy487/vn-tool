# AI5WIN/BE-YOND

## 目录定位

面向 `BE-YOND` 的工具目录，上级分类为 `AI5WIN`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `ai5winv1_arc_tool.py` | 封包/解包或格式工具 | AI5WIN v1 ARC Archive Tool - Unpack & Repack ============================================= Engine: AI5WIN v1 (e.g. LIME、早期 AI5WIN 作品) Format: MES.ARC / BG.ARC / BGM.ARC / VOICE.ARC |
| `ai5winv1_mes_extract.py` | 提取/解析 | AI5WIN v1 MES 文本提取工具 适配 GalTransl JSON: {id, name, message} MES 格式 (version 1 / opcode set v0, 从 AI5WINV1.exe 逆向): 外层: LZSS 压缩 (4KB window, 0xFEE 初始写指针) 内层: 无 header, bytecode 从 of |
| `ai5winv1_mes_inject.py` | 注入/回写 | AI5WIN v1 MES 文本注入工具 适配 GalTransl JSON: {id, name, message} 变长替换 + bytecode 跳转地址精确修正。 MES 格式 (version 1 / opcode set v0): 无 header, bytecode 从 offset 0 开始。 跳转地址相对于文件起始 (offset 0),  |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### ai5winv1_mes_extract.py
```bash
python ai5winv1_mes_extract.py <input.mes> [output.json]
python ai5winv1_mes_extract.py <mes_dir>   [json_dir]  (批量)
```
### ai5winv1_mes_inject.py
```bash
python ai5winv1_mes_inject.py <input.mes> <trans.json> [output.mes]
python ai5winv1_mes_inject.py <mes_dir>   <json_dir>   [output_dir]  (批量)
```

## 参数入口速查

### `ai5winv1_arc_tool.py`
- `'arc', help='Input ARC file'`
- `'outdir', help='Output directory'`
- `'indir', help='Input directory'`
- `'arc', help='Output ARC file'`
- `'--order', help='File order list (one filename per line`
- `'arc', help='Input ARC file'`
- `'arc', help='ARC file to verify'`
- `'refdir', help='Reference directory with extracted files'`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`traceback`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
