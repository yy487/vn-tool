# overflow/サマー・ラディッシュ・バケーション

## 目录定位

面向 `サマー・ラディッシュ・バケーション` 的工具目录，上级分类为 `overflow`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `xml_text.py` | 提取/解析 | XML 脚本文本提取/导入工具 格式: XML (<SCRIPT><BLOCK>...<RESOURCE>...<FUNCTION name="MESSAGE"/>) 对话: RESOURCE[INT=0] + GSCRIPT + STR(文本) → FUNCTION MESSAGE 选择: RESOURCE[INT=1] + GSCRIPT + STR(选 |

## 推荐流程

1. 按脚本文件名区分入口：extract 负责导出，inject 负责回写，*_tool/codec/common 作为格式工具或公共库。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `type`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### xml_text.py
```bash
python xml_text.py extract  <xml文件> [json文件]
python xml_text.py insert   <xml文件> <json文件> [输出xml]
python xml_text.py batch_e  <xml目录> <json输出目录>
python xml_text.py batch_i  <xml目录> <json目录> [输出目录]
```

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
