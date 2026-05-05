# love letter

## 目录定位

love letter 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `mgos_decode.py` | 图像/资源转换 | MGOS (MU Game Operation System) BMP Decoder - Pure Python Supports: Fd, Fc(?), 8P(?), BM formats Reverse engineered from loveletter.exe (0x4217E0, 0x423A10) Usage: python mgos_deco |

## 推荐流程

1. 如脚本存在加密/压缩层，先执行解密或解码步骤，再处理明文脚本。

## 命令示例

### mgos_decode.py
```bash
python mgos_decode.py input.bmp [output.png]
python mgos_decode.py --batch input_dir/ [output_dir/]
```

## 参数入口速查

### `mgos_decode.py`
- `'input', help='Input .bmp file or directory'`
- `'output', nargs='?', help='Output .png file or directory'`
- `'--batch', action='store_true'`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`PIL`。
使用图像或字体相关脚本前需安装 Pillow：`pip install pillow`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
