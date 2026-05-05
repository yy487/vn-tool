# FFA/C1WIN

## 目录定位

面向 `C1WIN` 的工具目录，上级分类为 `FFA`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `c1win_dat_tool.py` | 封包/解包或格式工具 | C1WIN/C1WIS DAT Archive Tool (天巫女姫 C1WIN Engine) 解包/封包 .DAT 存档文件 格式说明: .LST 索引文件: 每条目 22 字节 +0x00: char[14] 文件名 (ASCII, null-padded) +0x0E: u32 DAT内偏移 +0x12: u32 文件大小 .TAG 标签文件: 每条 |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `type`, `offset`, `index`, `raw`。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

### c1win_dat_tool.py
```bash
python c1win_dat_tool.py unpack C1WIN ./extracted
python c1win_dat_tool.py list C1WIS
python c1win_dat_tool.py repack C1WIN ./modified C1WIN_NEW
```

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
