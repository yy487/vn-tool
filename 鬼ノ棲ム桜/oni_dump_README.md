# ONI Engine 运行时资源 Dump 工具

## 概述

`oni_dump.c` 是一个 DLL 注入工具，通过 hook 游戏引擎的关键函数，在运行时自动 dump 所有被加载的图像资源。

## 它能做什么

| 功能 | 实现方式 |
|------|----------|
| 记录所有文件访问 | Hook `CreateFileA` (IAT hook) |
| Dump 解码后的图像 | Hook `FUN_0040C1E0` (inline hook) → 函数返回后从全局缓冲区 `0x429B50` 读取像素 |
| 输出格式 | BMP 文件 (BGR bottom-up, 与引擎内部格式一致) |

## 为什么需要 DLL hook 而不是直接用 gr2_tool.py？

**gr2_tool.py 能处理的：**
- 文件系统上的独立 `.gr2` 文件

**gr2_tool.py 处理不了、但 DLL hook 能处理的：**
- `oni.dat` 内嵌图像（带 `onifr2`/`onifr` 前缀，XOR 加密后打包在脚本数据中）
- 16bpp 图像经引擎查找表转换后的真实 24bpp 结果
- 运行时动态合成的图像（如立绘 + alpha 遮罩混合后的最终结果）

## 编译

### MSVC (推荐)
```cmd
cl /LD /O2 oni_dump.c /link user32.lib gdi32.lib kernel32.lib /out:oni_dump.dll
```

### MinGW
```cmd
gcc -shared -o oni_dump.dll oni_dump.c -luser32 -lgdi32 -lkernel32 -O2
```

## 注入方式

### 方式 A：DLL 劫持 (推荐，最安全)

1. 用 AheadLib 打开游戏目录下的某个系统 DLL（如 `winmm.dll`），生成转发源码
2. 在生成的 `DllMain` 中加入 `LoadLibraryA("oni_dump.dll");`
3. 编译替换到游戏目录

或者更简单——如果游戏目录没有自带 DLL：
1. 把 `oni_dump.dll` 改名为 `version.dll`（或 `winmm.dll` / `dxgi.dll`）
2. 在 `DllMain` 中加入对原始系统 DLL 的转发

### 方式 B：修改导入表

```cmd
:: 用 Microsoft Detours 的 setdll.exe
setdll.exe /d:oni_dump.dll ONI.exe
```

注意：如果 EXE 有壳或签名校验，此方法可能失败。

### 方式 C：启动器注入

编写一个小启动器，用 `DetourCreateProcessWithDllW` 启动游戏并注入 DLL。

## 输出

运行游戏后，在游戏目录下会生成 `_dump/` 文件夹：

```
_dump/
├── dump_log.txt           # 完整日志（所有文件访问记录 + 图像dump记录）
├── images/
│   ├── 0001_sakura1.bmp   # 按加载顺序编号 + 原始文件名
│   ├── 0002_sakura2.bmp
│   ├── 0003_yn-11.bmp
│   └── ...
└── raw/                   # 预留（可扩展dump其他格式）
```

## 日志示例

```
=== ONI Engine Resource Dumper ===
[+] CreateFileA IAT hook installed
[+] ImageLoad inline hook installed at 0x0040C1E0

[CreateFileA] sakura1.gr2
[ImageLoad] mode=1 basename="sakura1"
  → 成功: 640x480 24bpp
  → DUMP: _dump\images\0001_sakura1.bmp (921600 bytes)

[CreateFileA] yn-11.gr2
[ImageLoad] mode=1 basename="yn-11"
  → 成功: 640x480 24bpp
  → DUMP: _dump\images\0002_yn-11.bmp (921600 bytes)
```

## 技术细节

### Hook 点选择理由

**为什么 hook `FUN_0040C1E0` 而不是 `CreateFileA` + `ReadFile`？**

`FUN_0040C1E0` 是图像加载的高层入口，它的第二个参数就是文件基础名（如 `"yn-11"`），函数返回后全局缓冲区 `0x429B50` 就包含了解码后的完整像素数据。一个 hook 点就能同时获取文件名和像素数据。

如果 hook `CreateFileA` + `ReadFile`，需要追踪文件句柄、手动拼接多次 ReadFile 的数据、自己做 LZSS 解压——工作量大且容易出错。

### 全局缓冲区布局

| 地址 | 大小 | 内容 |
|------|------|------|
| `0xBB7300` | 0x28 | BITMAPINFOHEADER（宽高、bpp 信息） |
| `0xB929A0` | 0x24 | Extra header（游戏标题等） |
| `0x429B50` | ~2MB | 主像素缓冲区（SetDIBitsToDevice 的数据源） |
| `0x82FC5C` | ~2MB | 临时缓冲区（LZSS 解压输出 / 16→24bpp 转换源） |

### Inline Hook 实现

使用经典的"unhook-call-rehook"模式：
1. 保存目标函数前 16 字节
2. 覆写前 5 字节为 `JMP rel32` 到 hook 函数
3. 在 hook 函数内需要调用原函数时：恢复原始字节 → 调用 → 重新安装 hook

这种方法简单可靠，缺点是非线程安全（在恢复/重装期间如果有其他线程调用同一函数会崩溃）。对于单线程的 Galgame 引擎来说完全没问题。

## 注意事项

- 此工具仅适用于 `鬼ノ棲ム桜` 的特定 EXE 版本，地址是硬编码的
- 如果游戏更新或使用不同版本的 EXE，需要重新确认地址
- dump 的 BMP 文件是 BGR bottom-up 格式，可直接用任何图片查看器打开
- 立绘文件的右半部分是 alpha 遮罩，不是图像内容的一部分
