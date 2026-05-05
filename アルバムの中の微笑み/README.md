# アルバムの中の微笑み

## 目录定位

アルバムの中の微笑み 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `scn_extract.py` | 提取/解析 | scn_extract.py - Seraph引擎 ScnPac 文本提取 用法: python scn_extract.py SCNPAC.DAT -o texts.json 从ScnPac.Dat中解包所有脚本entry → LZ解压 → 扫描VM opcode 0x00提取inline CP932文本 按opcode 0x15(WAIT_CLICK)自 |
| `scn_inject.py` | 注入/回写 | scn_inject.py - Seraph引擎 ScnPac 文本注入 用法: 等长注入(安全): python scn_inject.py SCNPAC.DAT texts.json -o SCNPAC_new.DAT --fixed 变长注入: python scn_inject.py SCNPAC.DAT texts.json -o SCNPAC_n |
| `scnpac_tool.py` | 封包/解包或格式工具 | scnpac_tool.py - Seraph引擎 ScnPac.Dat 解包/封包工具 ScnPac.Dat 结构: u32 count 脚本条目数 u32[count+1] offsets 偏移表(末项为sentinel) bytes entries 脚本条目数据(entry[i] = data[offsets[i]:offsets[i+1]]) byt |
| `seraph_lz.py` | 辅助脚本 | seraph_lz.py - Seraph引擎 LZ 压缩/解压模块 格式: Header: u32 LE 解压后大小 Body: ctrl & 0x80 = 1: 回引 (2字节) offset = ((u16 >> 5) & 0x3FF) + 1 [1..1024] length = (u16 & 0x1F) + 1 [1..32] ctrl & 0x8 |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`message`, `file`, `offset`, `index`, `raw`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python scn_extract.py --help
```
```bash
python scn_inject.py --help
```
```bash
python scnpac_tool.py --help
```

## 参数入口速查

### `scn_extract.py`
- `'scnpac', help='ScnPac.Dat 路径'`
- `'-o', '--output', default='scn_texts.json', help='输出JSON路径'`
### `scn_inject.py`
- `'scnpac', nargs='?', help='原始 ScnPac.Dat 路径'`
- `'texts', help='翻译后的 JSON 路径'`
- `'-o', '--output', default='SCNPAC_new.DAT', help='输出路径'`
- `'-e', '--encoding', default='cp932', help='目标编码 (默认cp932`
- `'--fixed', action='store_true', help='等长注入模式(安全`
- `'--fix-json', default='fix.json', help='截断句子导出路径'`
- `'--apply-fix', metavar='FIX_JSON', help='把fix.json写回texts.json'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
