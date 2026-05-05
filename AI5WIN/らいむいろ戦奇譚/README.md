# AI5WIN/らいむいろ戦奇譚

## 目录定位

面向 `らいむいろ戦奇譚` 的工具目录，上级分类为 `AI5WIN`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `lime_arc.py` | 封包/解包或格式工具 | AI5WIN v2 Mes.Arc 解包/封包工具 (不做LZSS处理) ARC中存储的就是LZSS压缩后的原始数据, 本工具只做索引解密和数据分割/拼接。 LZSS解压/压缩由 lime_extract / lime_inject 负责。 条目 0x1C字节: name(20B)^0x03 + size(4B)^0x33656755 + offset(4B |
| `lime_extract.py` | 提取/解析 | AI5WIN v2 MES 文本提取工具 输入: LZSS压缩的MES文件 (直接从ARC解包的原始数据) 输出: GalTransl兼容JSON 用法: python lime_extract.py <input.mes> [output.json] python lime_extract.py <mes_dir> <json_dir> (批量) |
| `lime_inject.py` | 注入/回写 | AI5WIN v2 MES 文本注入工具 输入: LZSS压缩的原始MES + 翻译JSON 输出: LZSS压缩的MES (伪压缩, 全literal) 内部流程: LZSS解压 → 变长文本替换+偏移修正 → LZSS伪压缩 用法: python lime_inject.py <original.mes> <translated.json> [outpu |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### lime_arc.py
```bash
python lime_arc.py unpack <input.arc> [output_dir]
python lime_arc.py pack   <input_dir>  [output.arc]
```
### lime_extract.py
```bash
python lime_extract.py <input.mes> [output.json]
python lime_extract.py <mes_dir>   <json_dir>     (批量)
```
### lime_inject.py
```bash
python lime_inject.py <original.mes> <translated.json> [output.mes]
python lime_inject.py <mes_dir> <json_dir> <output_dir>  (批量)
```

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
