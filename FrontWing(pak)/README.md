# FrontWing(pak)

## 目录定位

FrontWing(pak) 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `csb_extract.py` | 提取/解析 | csb_extract.py - Frontwing ADV CSB 文本提取 ============================================= Engine: FRONTWING_ADV (SeparateBlue etc.) Format: CSB (Compiled Script Binary), Shift-JIS Usag |
| `csb_inject.py` | 注入/回写 | csb_inject.py - Frontwing ADV CSB 文本注入 ============================================ Engine: FRONTWING_ADV (SeparateBlue etc.) Format: CSB (Compiled Script Binary) 跳转全部基于字符串标签名 → 变长 |
| `pak_tool.py` | 封包/解包或格式工具 | pak_tool.py - Frontwing ADV Engine PAK Archive Tool ===================================================== Engine: FRONTWING_ADV (SeparateBlue / セパレイトブルー) Format: PAK ("vav\0" magic |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### csb_extract.py
```bash
python csb_extract.py <input.csb> [output.json]
python csb_extract.py <input_dir> [output_dir]   # 批量
```
### csb_inject.py
```bash
python csb_inject.py <orig.csb> <trans.json> [output.csb] [--encoding gbk]
python csb_inject.py <orig_dir> <json_dir> [output_dir] [--encoding gbk]
```
### pak_tool.py
```bash
python pak_tool.py unpack <input.pak> [output_dir]
python pak_tool.py pack   <input_dir> <output.pak> [--order original.pak]
```

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
