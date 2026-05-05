# ego/twin way重置

## 目录定位

面向 `twin way重置` 的工具目录，上级分类为 `ego`。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `scr2_codec (1).py` | 公共库/编解码 | scr2_codec.py — Studio e.go! 'SCR ' v1 脚本底层解析 跟 BSF1 是完全不同的引擎 (那个是 tw.exe / Daytalk 系列, magic='BSF1')。 本模块只负责扫描文本条目, 不做完整 VM 反汇编。 文件结构 (Ay_01.scr 实测): +0x00 'SCR ' magic +0x04 u32  |
| `scr2_inject (1).py` | 注入/回写 | scr2_inject.py — Studio e.go! 'SCR ' v1 文本等长注入器 策略: 等长替换。译文 cp932 字节数 ≤ 原文字节数, 不足部分用半角空格补齐。 超长直接报错跳过该条。 子命令: single 注入单个 scr batch 批量注入整个目录, 无 JSON 的 scr 原样复制 export_overflow 扫一遍,  |
| `scr2_inject (2).py` | 注入/回写 | scr2_inject.py — Studio e.go! 'SCR ' v1 文本等长注入器 策略: 等长替换。译文 cp932 字节数 ≤ 原文字节数, 不足部分用半角空格补齐。 超长直接报错跳过该条。 子命令: single 注入单个 scr batch 批量注入整个目录, 无 JSON 的 scr 原样复制 export_overflow 扫一遍,  |

## 推荐流程

1. 只修改翻译字段后运行 inject/asm 类脚本回写；原文字段用于定位与校验，不建议改动。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`。

## 命令示例

### scr2_inject (1).py
```bash
python scr2_inject.py single Ay_01.scr ay_01.json Ay_01_new.scr
python scr2_inject.py batch  scr_dir/  json_dir/  out_dir/
python scr2_inject.py export_overflow scr_dir/ json_dir/ fix.json
python scr2_inject.py apply_fix fix.json json_dir/
```
### scr2_inject (2).py
```bash
python scr2_inject.py single Ay_01.scr ay_01.json Ay_01_new.scr
python scr2_inject.py batch  scr_dir/  json_dir/  out_dir/
python scr2_inject.py export_overflow scr_dir/ json_dir/ fix.json
python scr2_inject.py apply_fix fix.json json_dir/
```

## 参数入口速查

### `scr2_inject (1).py`
- `'scr'`
- `'json'`
- `'out'`
- `'scrdir'`
- `'jsondir'`
- `'outdir'`
- `'scrdir'`
- `'jsondir'`
- `'out'`
- `'fix'`
- `'jsondir'`
### `scr2_inject (2).py`
- `'scr'`
- `'json'`
- `'out'`
- `'scrdir'`
- `'jsondir'`
- `'outdir'`
- `'scrdir'`
- `'jsondir'`
- `'out'`
- `'fix'`
- `'jsondir'`

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
