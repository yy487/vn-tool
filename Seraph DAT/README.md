# Seraph DAT

## 目录定位

Seraph DAT 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `cf_decode.py` | 图像/资源转换 | Seraph Engine - CF/CT/CB/CC Image Decoder Game: WAGAMAJO (わがまま女にもほどがある) Engine: Seraph (seraph.exe / Selaphim) CF format header (0x10 bytes): 0x00 2B signature "CF" (0x4643) 0x02 2 |
| `seraph_dat_tool_v2.py` | 封包/解包或格式工具 | Seraph Engine - ArchPac.dat Unpacker v2 Supports automatic index_offset detection from ScnPac.Dat ArchPac index format (at index_offset): [ncat:u32] - number of categories [total:u |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 如脚本存在加密/压缩层，先执行解密或解码步骤，再处理明文脚本。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python cf_decode.py --help
```
```bash
python seraph_dat_tool_v2.py --help
```

## 参数入口速查

### `cf_decode.py`
- `'input', help='Input .cf file or directory'`
- `'-o', '--output', help='Output file/directory'`
- `'-b', '--batch', action='store_true', help='Batch decode directory'`
- `'--bmp', action='store_true', help='Save as BMP instead of PNG'`
- `'--info', action='store_true', help='Show header info only'`
### `seraph_dat_tool_v2.py`
- `'archpac', help='Path to ArchPac.dat'`
- `'output', nargs='?', default=None, help='Output directory'`
- `'-i', '--index-offset', type=lambda x: int(x, 0`
- `'-s', '--scnpac', default=None, help='Path to ScnPac.Dat for auto-detecting index_offset'`
- `'-l', '--list', action='store_true', help='List files only'`
- `'-v', '--verify', action='store_true', help='Verify index integrity'`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`PIL`。
使用图像或字体相关脚本前需安装 Pillow：`pip install pillow`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
