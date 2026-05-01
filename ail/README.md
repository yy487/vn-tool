# AILSystem 通用文本提取 / 注入工具

这套工具已经从原来的 BONDAGE 专用脚本改造成通用 AILSystem 脚本工具，同时保留原来的 JSON 翻译格式。

## 主要文件

| 文件 | 作用 |
|---|---|
| `ail_extract.py` | 通用 AIL 脚本文本提取器，输出旧格式 JSON |
| `ail_inject.py` | 通用 AIL 脚本文本注入器，支持 `varlen` / `fixed` / `append` |
| `ail_script_core.py` | 通用解析核心：header、label、主 OP、表达式、文本引用扫描 |
| `ail_opcode_tables.py` | 从 AIL_Tools `Script.cs` 迁移的 function/sub-op 表 |
| `bondage_extract.py` | 兼容入口，默认 `--profile bondage` |
| `bondage_inject.py` | 兼容入口，默认 `--profile bondage` |
| `bondage_batch.py` | 原批处理脚本，继续可用 |
| `snl_tool.py` | SNL/DAT 解包封包工具 |
| `ail_lzss.py` | AIL LZSS 编解码 |

## JSON 输出格式

提取结果仍然是原工具使用的列表 JSON：

```json
[
  {
    "id": 0,
    "pc": 1234,
    "sub": 1,
    "kind": "msg",
    "text_off": 5678,
    "name": "幸江",
    "name_pc": 1200,
    "name_text_off": 5600,
    "message": "译文写这里",
    "src_msg": "原文"
  }
]
```

字段说明：

- `pc`：主 opcode 在 bytecode 区内的相对偏移。
- `sub`：function/sub opcode。
- `kind`：`msg` / `title` / `msg_other`。
- `text_off`：文本池内相对偏移。
- `name*`：由 `【名字】 + 台词` 自动配对生成。
- `message`：翻译工作字段，注入时读取这个字段。
- `src_msg`：原文备份。

## 通用提取

```bash
python ail_extract.py 0081.bin ./json --version 2 --encoding cp932 --profile generic
```

常用参数：

```bash
--version 0|1|2       AIL_Tools 里的 function 表版本，默认 2
--encoding cp932      文本编码，默认 cp932
--profile generic     通用语义分类
--profile bondage     保留 BONDAGE 项目的 title/name 习惯
--scan labels         从 label 入口扫描
--scan linear         从 bytecode 起点线性扫描
--scan both           label + linear 合并去重，默认
--resync              解析失败后逐字节重同步，可能产生误判
```

BONDAGE 旧入口仍可用：

```bash
python bondage_extract.py 0081.bin ./json
```

## 通用注入

```bash
python ail_inject.py inject 0081.bin ./json/0081.json ./out/0081.bin --version 2 --encoding cp932 --profile generic --mode varlen
```

三种注入模式：

| 模式 | 说明 | 适用场景 |
|---|---|---|
| `varlen` | 重建整个文本池并修补识别到的全部引用 | 提取覆盖完整时使用 |
| `fixed` | 原槽位覆盖，超长截断，偏移不变 | 最稳保底模式 |
| `append` | 保留原文本池，把变化文本追加到末尾，只修补识别到的引用 | 通用汉化推荐的安全变长模式 |

示例：

```bash
# 变长重建
python ail_inject.py inject 0081.bin json/0081.json out/0081.bin --mode varlen

# 等长截断
python ail_inject.py inject 0081.bin json/0081.json out/0081.bin --mode fixed

# 追加模式，更适合 opcode 覆盖还没完全确认的游戏
python ail_inject.py inject 0081.bin json/0081.json out/0081.bin --mode append
```

BONDAGE 旧入口仍可用：

```bash
python bondage_inject.py inject 0081.bin json/0081.json out/0081.bin --mode append
```

## name 表

提取会自动生成：

```text
0081_names.json
```

格式：

```json
{
  "幸江": {
    "count": 12,
    "translation": "幸江"
  }
}
```

注入时会自动寻找同名 `_names.json`。也可以手动指定：

```bash
python ail_inject.py inject 0081.bin json/0081.json out/0081.bin --names json/0081_names.json
```

## 编码与映射

默认按 CP932 写回：

```bash
--encoding cp932
```

如果要严格检查简中字符是否能编码，不希望静默变成 `?`：

```bash
--errors strict
```

如果你的路线是“CP932 注入 + 字符映射到简体”，可以准备一个映射表：

```json
{
  "你": "偁",
  "们": "們"
}
```

然后注入时使用：

```bash
python ail_inject.py inject 0081.bin json/0081.json out/0081.bin --map table.json --errors strict
```

## Round-trip 测试

```bash
python ail_inject.py roundtrip 0081.bin --version 2 --encoding cp932 --profile generic
```

BONDAGE 兼容入口：

```bash
python bondage_inject.py roundtrip 0081.bin
```

## 相比原版的关键变化

1. `0x0A / 0x0B / 0x0C / 0x10` 已按 AIL_Tools 逻辑改成表达式参数，不再当固定 `u16`。
2. `0x05 store_f` 现在会继续解析后面的 function/sub-op，不再直接中止扫描。
3. 表达式消费改为结构化解析：`0x00 reg mask`、`0xFF` 结束、其他 flag 后跟 operator。
4. function/sub-op 表迁移自 AIL_Tools，`version=2` 覆盖 `0x00..0xFF`。
5. 新增 `append` 注入模式，降低通用化初期漏引用造成的风险。
6. 输出 JSON 仍保持原来的翻译工作流格式。
