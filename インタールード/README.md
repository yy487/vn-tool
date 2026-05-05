# インタールード

## 目录定位

インタールード 目录下的引擎/游戏工具集合。

本 README 根据本目录内 Python 源码的实际入口、参数、注释和数据结构整理，用于说明当前目录工具的用途与推荐使用顺序。

## 文件分工

| 文件 | 定位 | 说明 |
|---|---|---|
| `interlude_unpack.py` | 封包/解包或格式工具 | Interlude Engine data.img / *.pak 解包工具 逆向自 InterludeWin.exe 格式说明： - 文件开头是索引表（Index Table），可能经过旋转密钥加密 - 索引表大小存储在偏移 0x0C 处（解密后），按 0x800 对齐读取 - 每个条目 0x14 (20) 字节： [0x00 - 0x0B] 12字节 文 |
| `vtv_batch.py` | 辅助脚本 | Interlude Engine VTV → PNG 批量转换工具 用法: python vtv_batch.py |
| `vtv_decode.py` | 图像/资源转换 | Interlude Engine VTV 图像解码工具 逆向自 InterludeWin.exe VTV格式： - [0x00-0xA7] 168字节外层头部（前4字节XOR后恰好呈现"OggS"假象） - [0xA8-...] 图片数据（前4字节被 XOR "UCAT" (55 43 41 54) 加密） 图片数据头（解密后）： - uint16 widt |

## 推荐流程

1. 先用封包工具解包原始资源，保留原始目录结构。
2. 如脚本存在加密/压缩层，先执行解密或解码步骤，再处理明文脚本。
3. 最后重新封包或复制回游戏目录测试。

## 文本/JSON 字段约定

源码中出现的主要字段：`name`, `offset`。
- `file/offset/index/end` 等字段用于定位、重定位或校验，除非明确知道格式含义，否则不要手改。

## 命令示例

该目录脚本未在源码注释中提供完整命令示例，可优先使用 `-h/--help` 查看参数：
```bash
python interlude_unpack.py --help
```
```bash
python vtv_batch.py --help
```
```bash
python vtv_decode.py --help
```

## 依赖提示

除 Python 标准库外，源码中检测到的外部/项目依赖模块：`ctypes`, `traceback`。

## 注意事项

- 操作前请备份原始封包、脚本和 EXE；注入/封包类脚本通常会直接生成可替换资源。
- 保持提取时的目录结构与文件名；多数注入器依赖相对路径、偏移或原文校验。
- 默认编码多为 CP932/Shift-JIS；若脚本提供 `--encoding`，除非目标游戏已确认，否则不要随意改成 GBK。
- 对等长/截断注入器，译文过长可能被截断、报错或破坏后续指令；非等长注入器也需要确认跳转/长度表是否已同步修正。
