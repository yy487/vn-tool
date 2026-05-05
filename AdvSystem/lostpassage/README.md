# AdvSystem/lostpassage

## 目录定位

面向 `lostpassage` 的工具目录，上级分类为 `AdvSystem`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `ac2_common.py` | 公共库/编解码 | ac2_common.py —— AdvSystem (LostPassage) 脚本处理共用模块 被 ac2_extract.py / ac2_inject.py 引用 文件格式: ac2_tool.py 解出的 CP932 明文脚本 (DATA\SCRIPT\*.TXT/*.STX) 行语法 (按"去前导 \t 后"内容判别): [Command] ar |
| `ac2_extract.py` | 提取/解析 | ac2_extract.py —— AdvSystem 脚本文本提取 用法: python ac2_extract.py <script_dir> <output.json> 输入: script_dir: ac2_tool.py unpack 解出的脚本目录 (含 DATA/SCRIPT/*.TXT 等) 输出 JSON (GalTransl 兼容): [ |
| `ac2_inject.py` | 注入/回写 | ac2_inject.py —— AdvSystem 脚本文本回填 用法: python ac2_inject.py <source_dir> <trans.json> <output_dir> 输入: source_dir : 原始脚本目录 (ac2_tool.py 解出的日文脚本) trans.json : ac2_extract.py 生成的 JSON |
| `ac2_tool.py` | 封包/解包或格式工具 | AdvSystem .ac2 归档 解包/封包工具 引擎：AdvSystem (LostPassage 及同族) 格式（小端）: Header (12B): u32 entry_count u32 unknown (=0x0C) u32 data_base_offset (= 12 + count*100) Index: count × 100 字节, 每个 |
| `bmp2png.py` | 图像/资源转换 | bmp2png.py —— BMP 批量/单文件转 PNG 用法: python bmp2png.py <input> [output] [--recursive] [--overwrite] [--delete-src] 参数: input 单个 .bmp 文件 或 目录 output 输出路径 (文件→文件, 目录→目录; 省略则与输入同位置, 仅改后缀 |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `index`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### ac2_extract.py
```bash
python ac2_extract.py <script_dir> <output.json>
```
### ac2_inject.py
```bash
python ac2_inject.py <source_dir> <trans.json> <output_dir>
```
### bmp2png.py
```bash
python bmp2png.py <input> [output] [--recursive] [--overwrite] [--delete-src]
python bmp2png.py EV016A.BMP                 # -> EV016A.png
python bmp2png.py EV016A.BMP out.png
python bmp2png.py ac1_out/ png_out/
python bmp2png.py ac1_out/ png_out/ --recursive
```

## 参数入口速查

### `ac2_extract.py`
- `'script_dir', help='脚本目录 (ac2 解包产物`
- `'output_json', help='输出 JSON 路径'`
### `ac2_inject.py`
- `'source_dir', help='源脚本目录 (原始日文`
- `'trans_json', help='译文 JSON'`
- `'output_dir', help='输出目录'`
- `'--encoding', default='cp932', help='输出文件编码 (默认 cp932; 中文汉化用 gbk`
### `ac2_tool.py`
- `'ac2'`
- `'ac2'`
- `'out_dir'`
- `'in_dir'`
- `'ac2'`
- `'--manifest', default=None`
- `'ac2'`
- `'tmp_dir'`
### `bmp2png.py`
- `'input', help='源 .bmp 文件或目录'`
- `'output', nargs='?', default=None, help='目标路径 (文件/目录, 省略则就地改后缀`
- `'--recursive', '-r', action='store_true', help='递归遍历子目录'`
- `'--overwrite', '-f', action='store_true', help='覆盖已存在的目标 PNG'`
- `'--delete-src', action='store_true', help='转换成功后删除源 BMP'`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`PIL`, `datetime`。
使用图像或字体相关脚本前需安装 Pillow：`pip install pillow`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
