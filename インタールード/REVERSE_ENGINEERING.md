# Interlude 引擎逆向分析报告

## 概述

本报告记录了对 NEC Interchannel 开发的 Interlude 引擎（`InterludeWin.exe`，VS2003 编译）的逆向工程过程，涵盖资源存档格式和自定义图像格式的完整分析。

逆向工具：IDA Pro / Ghidra  
目标文件：`InterludeWin.exe` (PE32, 384KB)

---

## 1. 资源存档格式 (data.img / PAK)

### 1.1 文件体系

引擎在初始化时（`FUN_00413f40`）按编号加载多个资源包：

```
编号0: script.pak   — 脚本
编号1: cg.pak       — CG图像
编号2: system.pak   — 系统资源
编号3: bgm.pak      — BGM音乐
编号4: voice.win    — 语音
编号5: title.pak    — 标题画面
编号7: data.img     — 万能大包（兜底）
```

当某个编号的 PAK 不存在时，引擎回退到 `data.img`（编号7）查找：

```c
// FUN_00405b50
if (*(int *)(&DAT_0054e7c0 + param_1 * 4) == 0) {
    uVar3 = 7;  // 回退到 data.img
}
```

### 1.2 多卷支持

引擎为每个资源包维护5个文件名槽位（`FUN_004052f0`），间隔 0x10 字节：

| 槽位 | 文件名示例 |
|------|-----------|
| 0 | `data.img`（主文件） |
| 1 | `data.001` |
| 2 | `data.002` |
| 3 | `data.003` |
| 4 | `data.004` |

读取时通过条目的卷编号字段选择对应文件。

### 1.3 索引表格式

索引表位于文件开头，结构如下：

**加密判断**：读取首字节，若 `< 0x30` 则整个索引表已加密。

**索引表大小**：解密后偏移 `0x0C` 处的 `uint32`，按 `0x800` 对齐读取。

**每条目 0x14 (20) 字节**：

```
偏移  大小    含义
0x00  12B     文件名（大写ASCII，\0填充）
0x0C  4B      packed_offset
              [10:0]  块内子偏移 (& 0x7FF)
              [31:11] 绝对偏移，0x800对齐 (& 0xFFFFF800)
0x10  4B      packed_size
              [23:0]  文件数据大小 (& 0xFFFFFF)
              [31:24] 卷编号 (>> 24)
```

**文件定位**：

```
实际文件偏移 = packed_offset（整体值即偏移+子偏移）
读取大小     = (packed_size & 0xFFFFFF + 0x7FF) & 0xFFFFF800  (向上0x800对齐)
目标卷文件   = 由 packed_size >> 24 选择
```

**条目遍历终止条件**：文件名首字节为 `\0`。

引擎使用二分查找（`FUN_00405540`）在排序后的索引表中定位文件。

### 1.4 加密算法

函数 `FUN_004052b0`，旋转密钥流加法加密：

```c
void decrypt(byte *data, int size) {
    uint key = 0x6E86CC2E;
    for (int i = 0; i < size; i++) {
        byte c = key & 0xFF;
        key = ROL32(key, 1);
        data[i] += c;           // 解密操作：加上密钥字节
        if ((i & 5) != 0) {
            key = ROL32(key, 1); // 条件额外旋转
        }
    }
}
```

- 初始密钥：`0x6E86CC2E`
- 每步左旋1位
- 当 `(byte_index & 5) != 0` 时额外左旋1位
- 解密为加法（`data[i] += key_byte`），加密为减法

**加密判断依据**：原始文件名首字符为大写字母（ASCII ≥ 0x30），加密后首字节 < 0x30。

---

## 2. VTV 图像格式

### 2.1 格式发现过程

data.img 解包后产生三种扩展名：`.vtv`（1291个）、`.bin`（196个）、`.msk`（20个）。

VTV 文件前4字节为 `4F 67 67 53`（"OggS"），表面上看是 Ogg Vorbis 音频。但通过以下证据确认为图像：

1. **代码引用**：`FUN_00410140(5, "wp0002.vtv")` 等调用明确将 VTV 作为图像加载
2. **文件数量**：1291个 VTV，远超合理的音频数量
3. **命名规律**：前缀包含 CK（立绘）、BG（背景）、EV（事件）等图像分类

### 2.2 UCAT XOR 伪装

`FUN_00410140` 的头部判断逻辑：

```c
if (data[1] - data[0] == 0x18 &&
    data[2] == data[1] &&
    data[3] - data[0] == 0x04) {
    // UCAT 头格式，图片数据从偏移 0xA8 开始
    // 前4字节需要 XOR "UCAT" (0x55, 0x43, 0x41, 0x54)
} else {
    // 简单格式，图片数据从偏移 0x10 开始
}
```

**关键发现**：`OggS`（`4F 67 67 53`）恰好满足 UCAT 判断条件：

```
[1]-[0] = 0x67-0x4F = 0x18 ✓
[2]==[1] = 0x67==0x67      ✓
[3]-[0] = 0x53-0x4F = 0x04 ✓
```

这不是巧合——`OggS` 就是原始图片头前4字节 XOR `UCAT` 的结果：

```
原始: 1A 24 26 07
XOR:  55 43 41 54  ("UCAT")
结果: 4F 67 67 53  ("OggS")
```

### 2.3 图片数据结构

偏移 0xA8（UCAT头）或 0x10（简单头）处，XOR 解密后：

```
偏移  大小    含义
0x00  2B      uint16 width
0x02  2B      uint16 height
0x04  2B      uint16 format
              高字节: 0x03 = 16位色, 其他 = 32位色(BGRA)
              bit7:   长度扩展启用标志
              低4位:  LZSS 偏移位宽 (bVar1)
0x06  2B      uint16 reserved
0x08  ...     LZSS 压缩数据
```

实测样本：`width=640, height=480, format=0x0583`（32位BGRA，bVar1=3）。

### 2.4 LZSS 变种压缩算法

函数 `FUN_00417840`，输入参数：

```c
void decompress(byte *compressed, byte *output, int output_size, byte format_low);
```

**数据布局**：

```
compressed + 0x00: int32  literal_offset  — 字面量区相对偏移
compressed + 0x04: ...    bitstream       — 控制位流区（uint16 数组）
compressed + literal_offset: ...          — 字面量区（未压缩字节）
```

**初始化**：

```c
bVar1 = format_low & 0xF;           // 偏移位宽（如3）
uVar7 = (1 << bVar1) - 1;           // 长度掩码（如7）
_param_4 = (format_low >= 0x80) ? uVar7 : 0xFFFFFFFF;  // 长度扩展阈值
```

**解压循环**：

1. **控制字读取**：每16bit用完后读取新的 `uint16`，按 `(int16) | 0xFFFF0000` 扩展
2. **bit=1（字面量）**：从字面量区复制1字节到输出
3. **bit=0（匹配引用）**：
   - 读取 `uint16`，低 `bVar1` 位 = 匹配长度码，高位右移 = 回溯偏移
   - 若回溯偏移为0，从下一个 `uint16` 读取实际偏移
   - 若长度码等于 `_param_4`，从字面量区读1字节扩展长度
   - 最终复制长度 = 长度码 + 3
   - 从输出缓冲区 `(当前位置 - 回溯偏移)` 处复制
4. 控制字右移1位，继续循环

**输出格式**：32位 BGRA 像素数据（alpha 通道固定 0x80），分辨率 640×480。

---

## 3. 文件类型总结

| 扩展名 | 数量 | 格式 | 说明 |
|--------|------|------|------|
| .vtv | 1291 | UCAT XOR + LZSS 压缩图像 | CG、立绘、背景、UI |
| .bin | 196 | 二进制数据 | 配置/脚本数据 |
| .msk | 20 | 遮罩图像 | 转场效果蒙版 |
| .wav | - | PCM 音频 | 语音 |

### VTV 文件名前缀含义

| 前缀 | 推测含义 | 数量 |
|------|---------|------|
| EA/EI/ET/EX/EP | 事件CG（Event） | 597 |
| TM | 角色立绘（Tama?） | 189 |
| IZ | 角色立绘（Izumi?） | 134 |
| CK | 角色立绘 | 59 |
| ABG/IBG/TBG/PBG/ZBG | 背景图（Background） | 147 |
| HR/KA/YK/NN/SM/FU/TH | 其他角色 | - |
| SG | 系统图形 | 30 |
| WP/AP | 壁纸/启动画面 | 17 |

---

## 4. 关键函数对照表

| 地址 | 函数名（推测） | 功能 |
|------|---------------|------|
| `0x004052B0` | `pak_decrypt` | 旋转密钥解密 |
| `0x004052F0` | `pak_open` | 打开并解析 PAK/IMG 索引表 |
| `0x00405540` | `pak_find_file` | 二分查找文件条目 |
| `0x00405B50` | `pak_read_file` | 从 PAK 读取完整文件 |
| `0x00405BE0` | `pak_read_partial` | 从 PAK 读取部分数据 |
| `0x00405CB0` | `file_get_size` | 获取文件大小 |
| `0x00405CF0` | `file_read` | 底层文件读取（fopen/fread） |
| `0x00409F00` | `image_decode` | 图像解码入口 |
| `0x00410140` | `vtv_load_image` | VTV 图像加载（含 UCAT 解密） |
| `0x00410240` | `vtv_load_layered` | VTV 分层图像加载 |
| `0x00413F40` | `engine_init` | 引擎初始化 |
| `0x00417840` | `lzss_decompress` | LZSS 变种解压 |
