# plantech/Rumble ～バンカラ夜叉姫～

## 目录定位

面向 `Rumble ～バンカラ夜叉姫～` 的工具目录，上级分类为 `plantech`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `plantech_msg_extract.py` | 提取/解析 | plantech_msg_extract.py v2 — PLANTECH 引擎 MESSAGE.H + MESSAGE.BIN 文本提取 两层切分模型 (v2 修正): block: 用 0xFF 0xFF 切, 引擎随机访问单位, H 槽位指向 block 起点 sentence: 用 0xFF 0xFC ([n]) 切, 显示/翻译单位, 一句话一个  |
| `plantech_msg_inject.py` | 注入/回写 | plantech_msg_inject.py v2 — PLANTECH MESSAGE 文本注入 注入流程 (匹配 v2 提取器的 block/sentence 两层模型): 1. 按 block_idx + sent_idx 排序 2. 同 block_idx 的 sentence 按 sent_idx 顺序拼接, 中间用 [n] 分隔 (最后一句之后是 |
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

### plantech_msg_extract.py
```bash
python plantech_msg_extract.py MESSAGE.H MESSAGE.BIN -o messages.json
```

## 参数入口速查

### `plantech_msg_extract.py`
- `'h_file'`
- `'bin_file'`
- `'-o', '--output', default='messages.json'`
### `plantech_msg_inject.py`
- `'json_file'`
- `'-o', '--output', default='out'`
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
