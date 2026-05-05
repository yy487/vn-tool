# 鬼ノ棲ム桜

## 目录定位

鬼ノ棲ム桜 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `gr2_tool.py` | 封包/解包或格式工具 | gr2_tool.py - 鬼ノ棲ム桜 (ONI engine) GR2 图像格式转换工具 GR2 格式结构: [0x00-0x27] BITMAPINFOHEADER (40 bytes) - 标准 Windows BMP 信息头 [0x28-0x4B] Extra header (36 bytes): +0x00 (8B) 游戏标题 (SJIS, nul |

## 推荐流程

1. 按脚本文件名区分入口：extract 负责导出，inject 负责回写，*_tool/codec/common 作为格式工具或公共库。

## 命令示例

### gr2_tool.py
```bash
python gr2_tool.py decode <input.gr2> [output.png]
python gr2_tool.py encode <input.png> [output.gr2]
python gr2_tool.py batch_decode <input_dir> [output_dir]
python gr2_tool.py batch_encode <input_dir> [output_dir]
python gr2_tool.py info <input.gr2>
```

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`PIL`。
使用图像或字体相关脚本前需安装 Pillow：`pip install pillow`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
