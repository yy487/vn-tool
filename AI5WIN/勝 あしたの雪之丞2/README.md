# AI5WIN 多 bank 位图字库 / CP932 借码位工作流

这版工具把旧的“GBK 写入 + 只生成 FONT00”改成：

```text
翻译 JSON
  -> scan_chars.py 统计规范化后的真实字符
  -> hanzi_replacer.py 生成 replace_map.json
  -> font_gen.py 用 replace_map.json 重建 FONT00/FONT01/FONT02
  -> ai5win_mes_inject.py 用同一个 replace_map.json 注入 MES
```

核心规则：

```text
真实中文 target_char
  -> replace_map.json 分配 CP932 source_char
  -> MES 实际写 source_char.encode('cp932')
  -> TBL 登记 source_char 码位
  -> FNT/MSK 对应 glyph 画 target_char
```

## 推荐命令

### 1. 解包

```bash
python ai5win_arc_tool.py unpack MES.ARC work/MES
python ai5win_arc_tool.py unpack DATA.ARC work/DATA
```

### 2. 提取文本

```bash
python ai5win_mes_extract.py work/MES work/json
```

翻译后假设输出在：

```text
trans/json
```

### 3. 扫描译文字符

```bash
python scan_chars.py trans/json build/charset.json
```

### 4. 生成 CP932 借码映射

优先使用 `subs_cn_jp.json`，缺字自动补漏：

```bash
python hanzi_replacer.py build/charset.json work/DATA build/replace_map.json --cnjp-map subs_cn_jp.json
```

### 5. 生成三套双字节 font bank

```bash
python font_gen.py build/replace_map.json msyh.ttc work/DATA build/DATA_FONT --banks FONT00,FONT01,FONT02 --size 22
```

输出：

```text
build/DATA_FONT/FONT00.TBL/FNT/MSK
build/DATA_FONT/FONT01.TBL/FNT/MSK
build/DATA_FONT/FONT02.TBL/FNT/MSK
build/DATA_FONT/FONTHAN.*              # 默认原样复制
build/DATA_FONT/build_manifest.json
build/DATA_FONT/replace_map.json
```

把生成的 `FONT*.TBL/FNT/MSK` 覆盖进 `work/DATA`。

### 6. Patch EXE 字库缓冲大小

如果 `font_gen.py` 输出显示 `appended > 0`，或者 `build_manifest.json` 中某个 bank 的 `expanded=true`，需要把 EXE 里的 `font_size_array` 同步改成新的解压后 raw size。

已知 `font_size_array` 文件偏移为 `0x532C4`，布局为 4 组，每组 `TBL/FNT/MSK` 三个 `uint32`：

```text
FONT00: 0x532C4 + 0x00
FONT01: 0x532C4 + 0x0C
FONT02: 0x532C4 + 0x18
FONTHAN:0x532C4 + 0x24
```

先预览：

```bash
python patch_exe_font_banks.py Ai5win.exe build/DATA_FONT/build_manifest.json --dry-run
```

确认后写出：

```bash
python patch_exe_font_banks.py Ai5win.exe build/DATA_FONT/build_manifest.json Ai5win_CHS.exe
```

### 7. 注入 MES

```bash
python ai5win_mes_inject.py work/MES trans/json build/MES_CHS --map build/replace_map.json
```

### 8. 回封包

```bash
python ai5win_arc_tool.py pack work/DATA DATA_CHS.ARC
python ai5win_arc_tool.py pack build/MES_CHS MES_CHS.ARC
```

## 重要说明

1. `ai5win_mes_inject.py` 已删除 GBK 回退逻辑。不能映射到 CP932 的字符会直接报错，不再静默写 `?`。
2. `ai5win_disasm.py` 的 op `0x01 TEXT` 已恢复 CP932 lead-byte 判断，不再用 `0x81-0xFE` 的 GBK 容错。
3. `font_gen.py` 对 `subs_cn_jp.json` 里借用的已存在码位会覆盖原 glyph；否则查表会先命中旧 glyph，无法显示中文。
4. `FONTHAN` 默认不改。正文中的 ASCII 会在 `text_normalize.py` 中全角化，尽量走双字节 bank。
5. 如果 `build_manifest.json` 显示某个 bank `expanded=true`，请运行 `patch_exe_font_banks.py`。它会按 `0x532C4` 起始的 4 组 `TBL/FNT/MSK` size 数组 patch `FONT00/FONT01/FONT02/FONTHAN`。


## v4 修正说明

v3 的 `font_gen.py` 只会把 `replace_map.json/chars` 里的“需要借码位字符”写入 FONT00/01/02，
但 `direct_cp932_chars` 会被注入器直接写入 CP932。如果某个 direct 字符不在当前 bank 的 TBL 中，
游戏会查表失败，表现为缺字、错字或仍显示借用源字。v4 已修正：

- mapped chars：继续按 `source_char -> target_char glyph` 覆盖/追加；
- direct CP932 chars：若 bank 已有则保留原 glyph，若缺失则用传入 TTF 补画并追加；
- 新增 `debug_encode.py` 用于检查某句话最终写入 MES 的 source 字符和 CP932 字节。

示例：

```bat
python debug_encode.py build
eplace_map.json "叮～咚～当～咚～"
python font_gen.py build
eplace_map.json alyce_humming.ttf E:\GAL\yuki2ont build\DATA_FONT --banks FONT00,FONT01,FONT02 --size 22
```


## v5 重要修正

v5 的 font_gen.py 不再只补 direct CP932 缺字；对于译文中出现的 direct CP932 汉字，即使原 bank 已有同码位，也会用指定 TTF 重绘该 glyph。否则会出现 `叮` 这类字在游戏中显示成原字库旧字形的问题。

同时，mapped chars 的 source_char 码位会强制覆盖为 target_char glyph，不再依赖 replace_map 中的 overwrite_existing_glyph 标记。若画面仍显示繁体/借码源字，优先检查是否把 build/DATA_FONT 里的 FONT00/01/02.* 覆盖进 DATA 解包目录并重新封包。


## v6 重要修正：source/direct 码位冲突

如果 `replace_map.json` 中某个 `source_char` 同时也是 `direct_cp932_chars`，同一个 CP932 码位会被要求显示两个不同字形，必然造成“无显示成校”“逗号/借码字错位”等现象。

因此 v6 的 `hanzi_replacer.py` 会在生成映射时排除所有 direct CP932 字符作为借码位；`font_gen.py` 也会在发现旧 map 有冲突时直接报错。

建议每次更新到 v6 后重新执行：

```bat
python scan_chars.py trans_json build\charset.json
python hanzi_replacer.py build\charset.json orig_font buildeplace_map.json --cnjp-map subs_cn_jp.json
python check_map_conflicts.py buildeplace_map.json
python font_gen.py buildeplace_map.json alyce_humming.ttf orig_font build\DATA_FONT --banks FONT00,FONT01,FONT02 --size 22
```

## v7 修正

修正 `FontBank.append_glyph()` 的新增 glyph 索引错位问题。原始 FONT00/01/02 可能存在 `slot_count > TBL count` 的备用槽；新增 TBL code 时必须优先写入 `glyph_index == len(codes)` 的备用槽，而不能直接把 glyph 追加到 FNT/MSK 文件尾部。否则引擎查表得到的 index 会落到旧备用槽，导致新增字符整体错位显示。

可用 `inspect_font_mapping.py` 检查字符在各 bank 中的 code/index：

```bat
python inspect_font_mapping.py build\replace_map.json build\DATA_FONT "啊无，叮咚权"
```
