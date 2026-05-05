# AVC/欲情ペットライフ

## 目录定位

面向 `欲情ペットライフ` 的工具目录，上级分类为 `AVC`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `avc_codec.py` | 公共库/编解码 | AVC 引擎 (Adv.exe / SETSUEI 系列) 归档格式 codec 格式布局 (基于 Adv.exe 反编译 + 参考 GARbro ArcAVC.cs): 偏移 大小 内容 -------------------------------------------------------------- 0x00..0x08 8 skipped ( |
| `avc_extract.py` | 提取/解析 | AVC 引擎归档解包工具 用法: python avc_extract.py <input.dat> <output_dir> python avc_extract.py <input.dat> <output_dir> --save-key <key.bin> 输出: 将归档内每个文件释放到 output_dir; 可选 --save-key 保存 key |
| `avc_inject.py` | 注入/回写 | AVC 引擎归档封包工具 用法: # 用原始 dat 提取的 key 重新封包 (推荐, 可保持二进制一致): python avc_inject.py <input_dir> <output.dat> --use-key <key.bin> # 不指定 key 时,从原 dat 复制 key (再次推荐): python avc_inject.py <in |

## 推荐流程

1. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
2. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 命令示例

### avc_extract.py
```bash
python avc_extract.py <input.dat> <output_dir>
python avc_extract.py <input.dat> <output_dir> --save-key <key.bin>
```
### avc_inject.py
```bash
python avc_inject.py <input_dir> <output.dat> --use-key <key.bin>
python avc_inject.py <input_dir> <output.dat> --ref <original.dat>
python avc_inject.py <input_dir> <output.dat> --key-hex 877a000083580000
```

## 参数入口速查

### `avc_extract.py`
- `"input", help="输入 .dat 文件"`
- `"output_dir", help="输出目录"`
- `"--save-key", help="将 8 字节 key 保存到该路径", default=None`
- `"-q", "--quiet", action="store_true", help="静默模式"`
### `avc_inject.py`
- `"input_dir", help="输入目录 (含要打包的文件`
- `"output", help="输出 .dat 路径"`
- `"--use-key", help="从二进制文件读 8 字节 key"`
- `"--ref", help="从一个原始 dat 提取并复用 key/skip-bytes/padding (推荐: 严格 round-trip`
- `"--key-hex", help="直接给定 8 字节 key 的 hex 串 (16 字符`
- `"--order", help="可选: 指定文件加入顺序的 .txt", default=None`
- `"-q", "--quiet", action="store_true", help="静默模式"`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
