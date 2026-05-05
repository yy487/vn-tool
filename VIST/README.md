# VIST

## 目录定位

VIST 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `emc_tool.py` | 封包/解包或格式工具 | EMC (EMSAC-Binary Archive-2) 解包/封包工具 适用引擎: EntisGLS / VIST (EScriptV2) 格式标识: 文件头 'VIST' + 'EMSAC-Binary Archive-2' 文件扩展名: .emc 用法: 解包: python emc_tool.py unpack <input.emc> [output |
| `emi2png.py` | 图像/资源转换 | EMI (EMSAC-Image-2) → PNG 解码器 适用引擎: EntisGLS / VIST (EScriptV2) 支持: ERI_RUNLENGTH_GAMMA 编码 (coding=0x01), architecture=-1, 8/24/32bpp 用法: python emi2png.py <input.emi> [output.png] |
| `gds_text.py` | 提取/解析 | GDS 脚本文本提取/导入工具 适用引擎: EntisGLS / VIST (EScriptV2) 格式: UTF-16LE 明文脚本 (.gds) 用法: 提取: python gds_text.py extract <input.gds> [output.txt] 导入: python gds_text.py inject <orig.gds> <tra |

## 推荐流程

1. 按脚本文件名区分入口：extract 负责导出，inject 负责回写，*_tool/codec/common 作为格式工具或公共库。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `choice`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### emi2png.py
```bash
python emi2png.py <input.emi> [output.png]
python emi2png.py <input_dir> [output_dir]    (批量转换)
```
### gds_text.py
```bash
python gds_text.py inject_dir  <gds_dir> <txt_dir> [out_dir]
```

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`PIL`, `ctypes`。
使用图像或字体相关脚本前需安装 Pillow：`pip install pillow`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
