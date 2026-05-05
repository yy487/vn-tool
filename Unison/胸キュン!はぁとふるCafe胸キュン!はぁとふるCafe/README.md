# Unison/胸キュン!はぁとふるCafe胸キュン!はぁとふるCafe

## 目录定位

面向 `胸キュン!はぁとふるCafe胸キュン!はぁとふるCafe` 的工具目录，上级分类为 `Unison`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `lazy_common.py` | 公共库/编解码 | Softpal Lazy 引擎公用模板库 ======================================== 文件格式 (.VAL): +---------------------+ | Header 9 字节 | | u24 size_A | seg_A (字节码) 字节数 | u24 size_B | seg_B (字符串偏移表) 条目数  |
| `val_extract.py` | 提取/解析 | Lazy 引擎 .VAL 剧情文本提取工具 ================================ 用法: python3 val_extract.py <input_dir> <output_dir> [--min-items N] 行为: 遍历 <input_dir> 下所有 .VAL 文件 (无差别处理), 扫描每个文件中 由 0xdd op |
| `val_inject.py` | 注入/回写 | Lazy 引擎 .VAL 剧情文本注入工具 ================================ 用法: python3 val_inject.py <orig_val_dir> <translated_json_dir> <output_val_dir> [--encoding cp932|gbk] 行为: 1. 读取 <translated_ |
| `vct_extract.py` | 提取/解析 | Softpal Lazy 引擎 VCT 容器解包工具 格式: u8 ext_count {char letter, u16 first_entry_idx}[ext_count] (首字母索引加速表) u32 entry_count {char name[0x14], char ext[0x04], u32 offset, u32 size}[entry_c |
| `vct_pack.py` | 封包/解包或格式工具 | Softpal Lazy 引擎 VCT 容器封包工具 策略: - 优先读取 _vct_meta.json (解包时保存) 来 1:1 重建结构 - 没有元信息时, 自动按文件名首字母排序并重建 ext_table |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `offset`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python val_extract.py --help
```
```bash
python val_inject.py --help
```

## 参数入口速查

### `val_extract.py`
- `'input_dir', help='解包后的 .VAL 目录 (包含 _vct_meta.json`
- `'output_dir', help='输出 JSON 目录'`
- `'--min-items', type=int, default=1, help='文件至少有这么多条剧情才输出 JSON (默认 1, 即只要有剧情就输出`
### `val_inject.py`
- `'orig_dir', help='原始 .VAL 目录'`
- `'json_dir', help='翻译后的 JSON 目录 (含 _extract_index.json`
- `'output_dir', help='注入后的 .VAL 输出目录'`
- `'--encoding', default='cp932', choices=['cp932', 'gbk'], help='文本编码 (默认 cp932`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
