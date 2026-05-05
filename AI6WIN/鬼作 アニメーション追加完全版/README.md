# AI6WIN/鬼作 アニメーション追加完全版

## 目录定位

面向 `鬼作 アニメーション追加完全版` 的工具目录，上级分类为 `AI6WIN`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `ai6win_arc_tool.py` | 封包/解包或格式工具 | AI6WIN Engine ARC Archive Tool (解包/封包) ========================================== 引擎: AI6WIN (ELF / Silky / Silky Plus) 格式: .arc 资源包 功能: unpack (解包) / pack (封包) 注意: 本工具直接操作原始数据，不做  |
| `ai6win_extract.py` | 提取/解析 | AI6WIN MES 文本提取工具 输入: LZSS压缩的MES + __arc_index.json (提供uncompressed_size) 输出: GalTransl兼容JSON 用法: python ai6win_extract.py <input.mes> <arc_index.json> [output.json] python ai6win_ |
| `ai6win_inject.py` | 注入/回写 | AI6WIN MES 文本注入工具 输入: LZSS压缩的原始MES + 翻译JSON + __arc_index.json 输出: LZSS压缩的MES (伪压缩, 全literal) 内部流程: LZSS解压 → 变长文本替换+偏移修正 → LZSS伪压缩 用法: python ai6win_inject.py [--encoding cp932|gbk |
| `ai6win_inject_new.py` | 注入/回写 | AI6WIN MES 文本注入工具 (GalTransl 格式) 适配 GalTransl 翻译后的 JSON 格式: {name, message, src_msg} 按顺序逐条匹配注入, 以 cp932 编码写回。 用法: 单文件: python ai6win_inject_new.py <input.mes> <trans.json> <arc_ind |
| `akb_tool.py` | 封包/解包或格式工具 | akb_tool.py - AI6WIN AKB image format converter Supports: AKB → PNG (decode) and PNG → AKB (encode) AKB Format (0x20 header + LZSS compressed delta-encoded pixels): +0x00 u32 magic |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `offset`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

### ai6win_arc_tool.py
```bash
python ai6win_arc_tool.py unpack  <input.arc>  [output_dir]
python ai6win_arc_tool.py pack    <input_dir>  [output.arc]
python ai6win_arc_tool.py list    <input.arc>
python ai6win_arc_tool.py verify  <input.arc>
```
### ai6win_extract.py
```bash
python ai6win_extract.py <input.mes> <arc_index.json> [output.json]
python ai6win_extract.py <mes_dir> <arc_index.json> <json_dir>  (批量)
```
### ai6win_inject.py
```bash
python ai6win_inject.py [--encoding cp932|gbk] <orig.mes> <trans.json> <arc_index.json> [output.mes]
python ai6win_inject.py [--encoding cp932|gbk] <mes_dir> <json_dir> <arc_index.json> <output_dir>
```
### akb_tool.py
```bash
python akb_tool.py decode <input.akb> [output.png]
python akb_tool.py encode <input.png> [output.akb] [--flags 0x80000000] [--bg 00000000]
python akb_tool.py info <input.akb>
python akb_tool.py batch_decode <input_dir> [output_dir]
python akb_tool.py batch_encode <input_dir> [output_dir]
```

## 参数入口速查

### `akb_tool.py`
- `'input'`
- `'input'`
- `'output', nargs='?'`
- `'input'`
- `'output', nargs='?'`
- `'--flags', default=None, help='Hex flags (e.g. 80000000`
- `'--bg', default=None, help='Background BGRA hex (e.g. 00000000`
- `'--ox', type=int, default=0, help='Offset X'`
- `'--oy', type=int, default=0, help='Offset Y'`
- `'--iw', type=int, default=None, help='Inner width'`
- `'--ih', type=int, default=None, help='Inner height'`
- `'--literal', action='store_true', help='Use literal LZSS (safe, larger`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`PIL`, `ctypes`, `numpy`, `platform`, `traceback`。
使用图像或字体相关脚本前需安装 Pillow：`pip install pillow`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
