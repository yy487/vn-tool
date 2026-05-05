# AI5WIN/ドラゴンナイト4 Windows版

## 目录定位

面向 `ドラゴンナイト4 Windows版` 的工具目录，上级分类为 `AI5WIN`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `ai5winv4_arc_tool.py` | 封包/解包或格式工具 | AI5WIN v4 ARC 解包/封包工具 纯索引加密解密,不含LZSS解压缩——文件原样提取/打包。 用法: python ai5winv4_arc_tool.py unpack <input.ARC> <output_dir> python ai5winv4_arc_tool.py pack <input_dir> <output.ARC> ARC 格式 |
| `ai5winv4_mes_extract.py` | 提取/解析 | AI5WIN v4 MES 文本提取工具 适配 GalTransl JSON: {id, name, message} MES 格式 (version 2, 从 AI5WINV4.exe 逆向): 外层: LZSS 压缩 (4KB window, 0xFEE 初始写指针) 内层: [0x00-0x03] uint32 message_count [0x04- |
| `ai5winv4_mes_inject.py` | 注入/回写 | AI5WIN v4 MES 文本注入工具 适配 GalTransl JSON: {id, name, message} 变长替换 + header msg_offsets 修正 + bytecode 跳转地址精确修正。 跳转地址识别 (从 AI5WINV4.exe 逆向 + version 2 opcode 表): 完整 opcode 解析器遍历字节码, 精 |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `msg`, `message`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### ai5winv4_arc_tool.py
```bash
python ai5winv4_arc_tool.py unpack <input.ARC> <output_dir>
python ai5winv4_arc_tool.py pack   <input_dir>  <output.ARC>
```
### ai5winv4_mes_extract.py
```bash
python ai5winv4_mes_extract.py <input.mes> [output.json]
python ai5winv4_mes_extract.py <mes_dir>   [json_dir]  (批量)
```
### ai5winv4_mes_inject.py
```bash
python ai5winv4_mes_inject.py <input.mes> <trans.json> [output.mes]
python ai5winv4_mes_inject.py <mes_dir>   <json_dir>   [output_dir]  (批量)
```

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`traceback`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
