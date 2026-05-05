# AI6WIN/麻呂の患者はガテン系

## 目录定位

面向 `麻呂の患者はガテン系` 的工具目录，上级分类为 `AI6WIN`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `arc_codec.py` | 公共库/编解码 | AI6WIN / AI5WIN ARC archive-level codec. Only the archive index codec lives here: the filename cipher and the fixed index-entry field layout. Payload-level LZSS is a separate conce |
| `arc_extract.py` | 提取/解析 | AI6WIN / AI5WIN ARC extractor. Writes every payload as the exact bytes stored in the archive (no LZSS decompression). A sidecar __arc_index.json records compressed_size and uncompr |
| `arc_pack.py` | 封包/解包或格式工具 | AI6WIN / AI5WIN ARC packer. Reads __arc_index.json to preserve the original order, filenames, and size fields. Payloads are written verbatim — no LZSS. When a payload's on-disk siz |
| `arc_verify.py` | 字体/映射/补丁辅助 | Round-trip verifier for AI6WIN / AI5WIN .arc archives. Extracts to a temp dir, packs back, and compares the result to the original byte-for-byte. Because neither the extractor nor  |
| `lzss_ai.py` | 公共库/编解码 | Silky / AI-series LZSS decompressor. Used by text-extraction tools to read MES payloads out of the directory produced by arc_extract.py. The archive packer does NOT import this mod |
| `mes_asm.py` | 注入/回写 | AI6WIN MES assembler — inverse of mes_diss.disassemble(). Takes the disassembly dict (with possibly-modified string args) and emits a valid .mes byte stream. Performs variable-leng |
| `mes_diss.py` | 提取/解析 | AI6WIN MES disassembler. Walks the body and produces a list of instructions in order, each tagged with its raw body-relative offset. Offset-carrying operands are resolved to label  |
| `mes_extract.py` | 提取/解析 | AI6WIN MES text extractor. Produces one translator file per .mes: <name>.mes.json A JSON array of dialogue entries: [ {"id": 0, "name": "", "message": " 闇医者 彦麻呂"}, {"id": 1, "name" |
| `mes_inject.py` | 注入/回写 | AI6WIN MES text injector. Reverses mes_extract.py: source .mes + <n>.mes.json => translated .mes Every run re-disassembles the source .mes from scratch, walks its STR_PRIMARY opcod |
| `mes_opcodes.py` | 公共库/编解码 | AI6WIN MES script opcode table (version 1, "most games"). Derived from: - silky_mes_tools AI6WINScript.command_library v1 - Cross-validated by full static disassembly of stage00.me |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `offset`, `raw`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

### arc_extract.py
```bash
python arc_extract.py <archive.arc> [-o <out_dir>]
python arc_extract.py <archive.arc> --list
```
### arc_pack.py
```bash
python arc_pack.py <in_dir> <out.arc>        # needs __arc_index.json
python arc_pack.py <in_dir> <out.arc> --raw  # from scratch, no JSON
```
### mes_extract.py
```bash
python mes_extract.py <plain.mes>                   # writes <plain>.mes.json
python mes_extract.py <src_dir> -o <work_dir>       # batch
```
### mes_inject.py
```bash
python mes_inject.py <src_dir> -w <work_dir> -o <out_dir>
python mes_inject.py <src.mes> -w <dir_with_json> -o <out.mes>
python mes_inject.py <src.mes> -o <out.mes>
```

## 参数入口速查

### `arc_extract.py`
- `"archive"`
- `"-o", "--out", help="Output directory (default: <arc>_unpacked`
- `"-q", "--quiet", action="store_true"`
- `"--list", action="store_true", help="Print index only, no extract"`
### `arc_pack.py`
- `"src", help="Directory produced by arc_extract.py"`
- `"out", help="Output .arc path"`
- `"--raw", action="store_true", help="Ignore __arc_index.json; pack every file as plaintext entry",`
- `"-q", "--quiet", action="store_true"`
### `arc_verify.py`
- `"archive"`
### `mes_extract.py`
- `"path", help="A .mes file or a directory of them"`
- `"-o", "--out", help="Output directory for .mes.json files. " "Default: next to each source .mes."`
- `"-r", "--recursive", action="store_true", help="When path is a directory, descend into subdirectories"`
- `"-q", "--quiet", action="store_true"`
### `mes_inject.py`
- `"path", help="A .mes file or a source directory"`
- `"-o", "--out", help="Output file (single mode`
- `"-w", "--work-dir", help="Directory holding the .mes.json files from mes_extract. " "Default: next to each source .mes."`
- `"-r", "--recursive", action="store_true"`
- `"-q", "--quiet", action="store_true"`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
