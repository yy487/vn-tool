# plantech/点心铺

## 目录定位

面向 `点心铺` 的工具目录，上级分类为 `plantech`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `plantech_msg_extract_v4.py` | 提取/解析 | plantech_msg_extract.py v4 — PLANTECH MESSAGE 文本提取 v4 相对 v3: - 新增「角色名「内容」」识别 (PLANTECH 实际格式, 危ない百貨店 等) - 向后兼容 v2 【】 格式 和 ＠＠＠ 主人公 - name 识别为纯便利性增强, round-trip 字节级一致仍成立 - 更详细的统计日志 H  |
| `plantech_msg_inject_v4.py` | 注入/回写 | plantech_msg_inject.py v4 — PLANTECH MESSAGE 文本注入 v4 相对 v3: - 支持 name_style='kagi' 的重建 (角色名「内容」) - 向后兼容 bracket / hero / None - 旧 JSON (无 name_style 字段) 自动回退到 v3 行为 - 更清晰的校验错误报告 控制 |
| `plantech_pac_tool.py` | 封包/解包或格式工具 | plantech_pac_tool.py — PLANTECH 引擎 PAC 图像格式解包/封包 格式 (来自 GARbro/morkt 源码): PAC = 8 字节前缀 + 标准 BMP +0..4 : u32 = 0 (固定 0, ImageFormat.Signature 检查) +4..8 : u32 = bmp_size (与 BMP 头里 bf |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python plantech_msg_extract_v4.py --help
```
```bash
python plantech_msg_inject_v4.py --help
```
```bash
python plantech_pac_tool.py --help
```

## 参数入口速查

### `plantech_msg_extract_v4.py`
- `'h_file', help='MESSAGE.H 偏移表'`
- `'bin_file', help='MESSAGE.BIN 文本数据'`
- `'-o', '--output', default='messages.json'`
### `plantech_msg_inject_v4.py`
- `'json_file'`
- `'-o', '--output', default='out'`
- `'--h-size', type=int, default=None, help='H 文件字节数 (默认 3999996 = 999999 slot * 4`
- `'json_file'`
- `'orig_h'`
- `'orig_bin'`
### `plantech_pac_tool.py`
- `'input'`
- `'-o', '--output', help='输出 PNG (默认同名 .png`
- `'input'`
- `'-o', '--output', help='输出 PAC (默认同名 .pac`
- `'input_dir'`
- `'-o', '--output', required=True, help='输出目录'`
- `'--mode', choices=['decode', 'encode'], default='decode', help='decode: PAC->PNG (默认`
- `'--ext', default='.png', help='decode 时输出图片格式扩展名 (.png/.bmp/...`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`PIL`。
使用图像或字体相关脚本前需安装 Pillow：`pip install pillow`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
