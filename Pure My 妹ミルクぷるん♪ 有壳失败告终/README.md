# Pure My 妹ミルクぷるん♪ 有壳失败告终

## 目录定位

Pure My 妹ミルクぷるん♪ 有壳失败告终 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `bcs_extract.py` | 提取/解析 | bcs_extract.py - Tanuki Soft / Kaeru Soft / Rune .bcs 文本提取器 支持引擎容器: - BCS\0 + GMS\0 (老引擎, 双层 LZSS, 内层 invert) - TSV\0 + TNK\0 (新引擎, Blowfish key="TLibDefKey", 需 pycryptodome) 提取策略: |
| `bcs_inject.py` | 注入/回写 | bcs_inject.py - Tanuki Soft / Kaeru Soft / Rune .bcs 文本注入器 A 方案 (零风险): - 字符串池零共享 (实测验证), 每条 op=0x03 entry 独占自己的 offset - 译文 ≤ 原文字节: 原位覆盖 + NUL 填充 (offset 不变, 字符串池总大小不变) - 译文 > 原文字节 |
| `bcs_lzss.py` | 公共库/编解码 | bcs_lzss.py - Tanuki/Kaeru/Rune .bcs 用的 LZSS 编解码 参数 (与 BcsExtractor.cs / GARbro 一致): - 4KB 滑动窗口 - frame 初始全 0, framePos 起始 = 0xFEE - 每个 control byte 控制 8 个后续 token, LSB 先 bit=1: li |
| `g2_pack.py` | 封包/解包或格式工具 | g2_pack.py - Glib2 .g2 / .stx 资源包封包器 配合 g2_unpack.py 使用 (共享 hashes.txt + permutation 实现) 封包策略: - 完全重建 .g2: header (0x5C) + 文件数据区 + index - 文件名/层级结构: 从输入目录扫描得到 (与原包独立) - 文件 chunk ke |
| `g2_unpack.py` | 封包/解包或格式工具 | g2_unpack.py - Glib2 .g2 / .stx 资源包解包器 移植自 GARbro/ArcG2.cs (morkt) 格式概要: Header (0x5C, 整体加密 key=0x8465B49B): "GLibArchiveData2.\0" + version('0'/'1') + ... +0x14 Key3, +0x24 Key2,  |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `offset`, `index`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

### bcs_extract.py
```bash
python bcs_extract.py <input.bcs|dir> [-o outdir]
```
### bcs_inject.py
```bash
python bcs_inject.py <orig.bcs|dir> <json.json|dir> -o out_dir
```
### g2_pack.py
```bash
python g2_unpack.py extract orig.g2 -o files/   (新增 manifest 输出)
python g2_pack.py files/ -o new.g2 [--manifest files/_manifest.json]
```

## 参数入口速查

### `bcs_extract.py`
- `'input', help="单个 .bcs 文件或目录"`
- `'-o', '--output', default='.', help="输出目录 (默认当前`
- `'--overwrite', action='store_true', help="覆盖已存在"`
- `'-v', '--verbose', action='store_true'`
### `bcs_inject.py`
- `'bcs_input', help="原 .bcs 文件或目录"`
- `'json_input', help="译文 .json 文件或目录"`
- `'-o', '--output', required=True, help="输出目录"`
- `'--overwrite', action='store_true'`
- `'-v', '--verbose', action='store_true'`
- `'--encoding', default='cp932', help="译文编码 (默认 cp932; 中文汉化引擎打 GBK leadbyte patch 后用 gbk`
### `g2_pack.py`
- `'input_dir', help="包含所有要打包文件的目录 (g2_unpack 解出的`
- `'-o', '--output', required=True, help="输出 .g2 文件路径"`
- `'--manifest', help="原始 _manifest.json (复用 keys, 用于 round-trip`
- `'--version', type=int, default=1, choices=[0, 1]`
### `g2_unpack.py`
- `'input'`
- `'input'`
- `'-o', '--output', default='extracted'`
- `'-v', '--verbose', action='store_true'`

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`Crypto`, `random`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
