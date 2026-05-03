# Masq_scn.hxp 标准文本工作流工具 v4

面向 `マスカレード / Masq_scn.hxp` 的 Him5 + Himauri 脚本文本处理工具。

当前工作流：

```text
unpack 解包 -> extract 得到每个脚本一个 JSON -> inject 非等长注入到 bin -> pack 回封 HXP
```

默认编码为 `cp932`。

## 文件说明

```text
masq_common.py    公共 Him5/Himauri/文本扫描/偏移修正逻辑
masq_unpack.py    Masq_scn.hxp -> unpacked/*.bin + manifest.json
masq_extract.py   unpacked/*.bin -> texts/<script>.json
masq_inject.py    unpacked + texts -> patched/*.bin + manifest.json
masq_pack.py      patched/*.bin + manifest.json -> Masq_scn.new.hxp
masq_pipeline.py  一键：原 HXP + 已编辑 texts -> 新 HXP
```

## 1. 解包

```bat
python masq_unpack.py Masq_scn.hxp -o unpacked
```

输出：

```text
unpacked/
  manifest.json
  sc1_1.bin
  sc3_1.bin
  ...
```

## 2. 提取文本

```bat
python masq_extract.py unpacked -o texts
```

输出为每个脚本一个 JSON：

```text
texts/
  sc1_1.json
  sc1_3.json
  sc3_1.json
  ...
```

脚本 JSON 格式：

```json
{
  "_file": "sc3_1",
  "texts": [
    {
      "name": "沼田ヒロシ",
      "msg": "（ど、どうしよう……）",
      "_offset": 13344,
      "_end": 13420,
      "_kind": "message",
      "_sep": "\n",
      "_index": 1
    },
    {
      "name": "",
      "msg": "声のする方に行ってみる",
      "_offset": 13136,
      "_end": 13165,
      "_kind": "choice",
      "_sep": "",
      "_index": 2
    }
  ]
}
```

翻译时只改：

```text
name
msg
```

不要改：

```text
_file
_offset
_end
_kind
_sep
_index
texts 的顺序
```

其中 `_end` 用于精确定位原字符串结束位置，`_sep` 用于保留 name 和 msg 之间原本的换行分隔，`_index` 用于保持排序稳定；它们不属于翻译内容。

## 3. 注入到解包脚本

```bat
python masq_inject.py unpacked texts -o patched --report inject_report.json
```

默认 `--encoding cp932`。如果中文译文还没有经过 CnJpMap / 字符映射转换，直接注入简中大概率会因为 CP932 不可编码而失败。正式流程建议：

```text
中文翻译 JSON -> CnJpMap 映射为 CP932 可编码文本 -> masq_inject.py
```

默认修正已经确认的控制流偏移：`opcode 0x04 direct jump` 与 `opcode 0x05 switch table`。如果要开启额外泛 u24 扫描，手动加：

```bat
python masq_inject.py unpacked texts -o patched --generic-u24 --report inject_report.json
```

`--generic-u24` 只建议调试时使用；如果出现脚本 PC 越界或跳转异常，先关闭它。

## 4. 回封 HXP

```bat
python masq_pack.py patched -o Masq_scn.new.hxp
```

回封使用未压缩条目，保留 Him5 bucket/name/order 结构。

## 5. 一键注入模式

如果已经有编辑好的 `texts/`，可以直接：

```bat
python masq_pipeline.py Masq_scn.hxp texts -o Masq_scn.new.hxp
```

开启泛 u24 调试模式：

```bat
python masq_pipeline.py Masq_scn.hxp texts -o Masq_scn.new.hxp --generic-u24
```

## 偏移修正范围

`masq_inject.py` 做非等长替换后会：

```text
1. 重建脚本字节流
2. 修正 Himauri 头部 size：0x08..0x0A 的 u24be
3. 修正 opcode 0x04 直接跳转的 u24be target
4. 修正 opcode 0x05 switch case 表的 u24be target
5. 可选 --generic-u24：额外扫描疑似 u24be 脚本偏移字段，避开 CP932 字符串区域
```

## 推荐测试顺序

```text
1. 只改 sc1_1 开头独白，确认独白后的 opening/movie 播放不会卡死。
2. 只改 sc3_1 的两个选项文本，确认选项显示和分支跳转。
3. 再改一个普通 message，确认 name-msg 合成正常。
4. 按章节批量注入并检查 inject_report.json。
```


## v5 偏移修正说明

v5 开始不再用“扫描字节值 04/05”的方式识别跳转。Himauri 脚本开头存在标准控制流结构：

```text
03 <expr> <u24>          条件跳转
05 <expr> <u16 count> <u24 target> * count   大型 switch / 跳转表
```

`sc1_1` 开头就有一个 0x48 项的大型 switch 表，后面才是普通台词和 opening/movie 块。只修正台词后的 `04 00 0B FE` 不够；如果前面文本变长，脚本开头 switch 表中所有位于变长位置之后的 target 也必须同步重定位。

因此 v5 使用解释器语法解析：表达式 `FUN_00401c60`、字符串 `FUN_004021f0`、参数包 `FUN_00404880`，只在 opcode 边界上修正 `01/02/03/04/05/06/5E` 的 u24 target。`--generic-u24` 仍然保留为调试选项，但默认关闭。
