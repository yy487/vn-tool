# Interlude-Extractor

Interlude 引擎（Interlude / インタールード）的资源解包与图像解码工具集，基于对 `InterludeWin.exe` 的逆向工程开发。

## 功能

- **data.img / PAK 解包** — 支持加密索引表解密、多卷文件自动读取
- **VTV 图像解码** — 解码伪装为 OggS 的自定义压缩图像格式，输出 PNG
- **PAK 通用解包** — 支持 script.pak、system.pak、title.pak 等

## 快速开始

### 解包 data.img

```bash
python interlude_unpack.py data.img output_data
```

将 `data.img`、`data.001` 等卷文件放在同一目录下，工具会自动按卷号读取。

```bash
# 仅列出文件索引（不提取）
python interlude_unpack.py -l data.img

# 解包其他 PAK
python interlude_unpack.py script.pak output_script
```

### VTV 图像解码

```bash
# 单个文件
python vtv_decode.py ABG001B.VTV output.png

# 批量解码
python vtv_decode.py -batch vtv_input_dir/ png_output_dir/
```

### 批量转换（固定路径版）

编辑 `vtv_batch.py` 开头的 `INPUT_DIR` / `OUTPUT_DIR`，然后直接运行：

```bash
python vtv_batch.py
```

## 文件说明

| 文件 | 功能 |
|------|------|
| `interlude_unpack.py` | data.img / PAK 解包工具 |
| `vtv_decode.py` | VTV 图像解码工具（单文件 / 批量） |
| `vtv_batch.py` | VTV 批量转换脚本（可自定义路径） |
| `REVERSE_ENGINEERING.md` | 逆向分析报告 |

## 依赖

- Python 3.6+
- 无第三方库依赖（仅使用标准库 `struct`、`zlib`、`io`、`os`）

## 已知支持的游戏

- インタールード (Interlude) — NEC Interchannel, 2004

## License

MIT
