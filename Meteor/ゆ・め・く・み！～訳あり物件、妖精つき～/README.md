# Meteor/ゆ・め・く・み！～訳あり物件、妖精つき～

## 目录定位

面向 `ゆ・め・く・み！～訳あり物件、妖精つき～` 的工具目录，上级分类为 `Meteor`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `snr_text_extract.py` | 提取/解析 | UMakeMe! SNR 脚本 文本提取 用法: python snr_text_extract.py <unpacked_dir> <json_dir> 为 <unpacked_dir> 下每个 *.txt 生成 <json_dir>/<name>.json GalTransl 格式: [ {"name": "...", "message": "..."} |
| `snr_text_inject.py` | 注入/回写 | UMakeMe! SNR 脚本 文本注入 用法: python snr_text_inject.py <orig_unpacked_dir> <json_dir> <out_dir> 读 <orig_unpacked_dir>/*.txt (原始脚本), 读 <json_dir>/*.json (翻译后), 写 <out_dir>/*.txt (注入后脚本, |
| `umake_codec.py` | 公共库/编解码 | UMakeMe! / ARCHIVE engine DAT codec Adv1.exe (アトリエかぐや?) 系 / 实际来自 EXE 逆向: - 静态密钥: b"UMakeMe!" (PTR_s_UMakeMe__00488bec) - magic: b"ARCHIVE" (s_ARCHIVE_00488c60) 文件结构 (从 FUN_0041ca00 |
| `umake_extract.py` | 提取/解析 | UMakeMe! / ARCHIVE DAT 解包工具 用法: python umake_extract.py <input.dat> <output_dir> 会在 output_dir 下生成: <output_dir>/<filename> 每个条目解密后的原始数据 <output_dir>/_meta.json 重建所需的元数据 (顺序/tag8/t |
| `umake_pack.py` | 封包/解包或格式工具 | UMakeMe! / ARCHIVE DAT 封包工具 用法: python umake_pack.py <input_dir> <output.dat> input_dir 必须是 umake_extract.py 的输出目录, 包含: _meta.json 每个条目的原始数据文件 |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 运行 extract/diss 类脚本导出文本或中间结构，通常输出 JSON/TXT。
3. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。
4. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `message`, `index`, `voice`, `raw`。
- `msg/message` 通常是可修改译文字段，提取后默认等于原文或解析后的正文。

## 命令示例

### snr_text_extract.py
```bash
python snr_text_extract.py <unpacked_dir> <json_dir>
```
### snr_text_inject.py
```bash
python snr_text_inject.py <orig_unpacked_dir> <json_dir> <out_dir>
```
### umake_extract.py
```bash
python umake_extract.py <input.dat> <output_dir>
```
### umake_pack.py
```bash
python umake_pack.py <input_dir> <output.dat>
```

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
