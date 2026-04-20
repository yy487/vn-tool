# ADVWIN32引擎逆向分析报告
## 游戏: 木漏れ日の並木道 (Komorebi no Namikimichi)

---

## 1. 引擎架构

ADVWIN32是一个模块化的Galgame引擎，采用插件式DLL架构：

```
advwin32.exe (29KB) — 纯壳程序
    └─ LoadLibrary("system.unt") (215KB) — 引擎核心
        ├─ LoadLibrary("graphic.unt") (66KB) — 通用图像接口
        │   └─ 通过vtable提供30个图像操作函数
        ├─ LoadLibrary("mmedia.unt") (65KB) — 多媒体处理
        └─ LoadLibrary("DAT/*.FIL") — 功能插件
            ├─ DIBWORK.FIL (96KB) — MCG图像解码 ★核心目标
            ├─ TEXTWORK.FIL — 文本处理
            ├─ SETUPEX.FIL — 安装程序
            ├─ cappear/cross/mask/noise/shalala.fil — 画面特效
            └─ ...其他FIL插件
```

**关键发现过程：**
- advwin32.exe只有29KB，反汇编后发现只包含窗口创建和消息循环
- 唯一的业务逻辑是`LoadLibraryA("system.unt")`加载引擎核心
- system.unt通过字符串`"graphic.unt"`动态加载图像模块
- 最终通过`"DIBWORK.FIL"`（导出`CreateFilter/FilterFunc`）找到MCG解码

## 2. MRG封包格式

### 2.1 文件结构

```
Offset  Size  Description
0x00    4     Signature: "MRG\x00" (0x0047524D)
0x04    2     key1index (u16)
0x06    2     key2index (u16) — <2为v1格式
0x08    4     index_end (u32) — 目录+头的总大小
0x0C    4     file_count (u32)
0x10    var   加密目录 (index_end - 0x10 字节)
...           文件数据区
```

### 2.2 目录条目 (v1, 每条0x20字节)

```
Offset  Size  Description
0x00    0x0E  文件名 (null-terminated ASCII)
0x0E    4     解压后大小
0x12    1     压缩方式: 0=raw, 1=LZSS, 2=MrgDecoder, 3=MrgDecoder+LZSS
0x13    9     保留
0x1C    4     下一个文件的偏移量
```

目录末尾多存一个offset（文件总大小），用于计算最后一个文件的size。

### 2.3 目录加密

加密算法与MCG相同的ROL+XOR流密码，但密钥生成方式不同：

**已知明文攻击 (GuessKey)：**
目录最后4字节解密后必然等于文件总大小(little-endian)。从最后一个字节反向推导：

```python
v = ROL(index[-1], 1)
key = v ^ (file_size >> 24)
# 然后逐字节回溯: key -= (++remaining)
# 最终将key回溯到index[0]对应的初始值
```

这个方法是GARbro的实现，非常优雅——不需要任何硬编码密钥。

### 2.4 LZSS解压 (方法1)

标准LZSS，与MCG使用完全相同的算法：
- 4KB滑动窗口，初始全零，写入位置从0xFEE开始
- Flag字节LSB优先，bit=1为literal，bit=0为back-reference
- Back-ref: 2字节 `[lo, hi]` → offset = `lo | ((hi & 0x0F) << 8)`, length = `(hi >> 4) + 3`

## 3. MCG图像格式

### 3.1 头部结构 (0x40字节)

```
Offset  Size  Description
0x00    8     Signature: "MCG 1.01"
0x08    4     保留(0)
0x0C    4     Flags(1)
0x10    4     数据偏移 = 0x40
0x14    8     保留(0)
0x1C    4     Width
0x20    4     Height
0x24    4     BPP (24)
0x28    4     解压后原始大小 (= W × H × 3)
0x2C    12    保留(0)
0x38    4     文件总大小
0x3C    4     保留(0)
```

### 3.2 解密算法

**代码位置：** `DIBWORK.FIL` 的 `0x10004789` 函数

```
参数:
  [ebp+0x08] = 输出buffer指针
  [ebp+0x0C] = 加密数据指针（原地解密）
  [ebp+0x10] = 数据长度 (data_size - 1)
  [ebp+0x14] = 密钥种子 (key_seed)

算法 (x86汇编):
  mov ebx, [ebp+0x14]    ; bl = key_seed
  or  ebx, ebx
  je  skip_decrypt        ; seed=0则跳过解密
  mov eax, [ebp+0x0C]    ; 数据指针
  mov ecx, [ebp+0x10]    ; 循环计数 = data_size - 1
  mov esi, eax
  mov edi, eax            ; 原地解密 (src == dst)
.loop:
  lodsb                   ; al = *src++
  rol al, 1               ; 循环左移1位
  xor al, bl              ; 异或密钥字节
  add bl, cl              ; ★ 关键: cl = ecx低字节，随loop递减
  stosb                   ; *dst++ = al
  loop .loop              ; ecx--, if ecx≠0 goto .loop
```

**密钥递增规则的陷阱：**
`add bl, cl` 中的 `cl` 是 ECX 的低8位。由于 x86 的 `loop` 指令每次递减 ECX，
cl 的值每次迭代都在变化：

```
第1次: cl = (data_size-1) & 0xFF
第2次: cl = (data_size-2) & 0xFF
第3次: cl = (data_size-3) & 0xFF
...
```

这在C伪代码或Ghidra反编译中极易被忽略——反编译器通常不会注意到
loop指令对ECX的递减与循环体内cl读取之间的耦合。

**Python实现：**
```python
def mcg_decrypt(data, key_seed, count):
    bl = key_seed & 0xFF
    ecx = count
    for i in range(count):
        cl = ecx & 0xFF          # 每次循环都变！
        al = ROL(data[i], 1)
        al ^= bl
        bl = (bl + cl) & 0xFF
        data[i] = al
        ecx -= 1                  # 模拟loop指令
```

### 3.3 LZSS解压

解密后立即进行LZSS解压，算法与MRG目录项相同（见2.4节）。

### 3.4 像素排列

解压后为 **top-down BGR** 格式（非通常BMP的bottom-up），直接按行顺序读取即可。

### 3.5 密钥来源

密钥存储在引擎对象的 `+0x5C` 字段中：

```asm
; system.unt vtable[0x160] 方法:
mov eax, [ecx + 0x5C]    ; 直接读取对象成员
ret
```

该字段在引擎初始化时设置，值来源于可执行文件路径或注册表配置。
本游戏的密钥为 **0x7B** (123)。

## 4. 定位解码函数的过程

### 4.1 调用链追踪

```
advwin32.exe
  └─ LoadLibrary("system.unt") → GetProcAddress("CreateSysUnitForm")
      └─ system.unt 搜索 "MCG " 字符串
          → 找到MCG类型检测函数 (cmp edi, 0x2047434D)
          → 但该函数只做格式判断，不含解码逻辑
      └─ system.unt 搜索 "graphic.unt" / "DIBWORK.FIL"
          → 发现 LoadLibrary("graphic.unt") + GetProcAddress("CreateDIBUnitForm")
          → graphic.unt 是通用接口，不含MCG特定逻辑
      └─ system.unt 搜索 DAT目录下的FIL插件
          → 发现 DIBWORK.FIL 导出 CreateFilter/FilterFunc
```

### 4.2 DIBWORK.FIL内部定位

```
FilterFunc (导出)
  └─ 0x100020B0 (主处理)
      └─ dispatch table (11个功能号 0-10)
          └─ 功能[1] = 0x10002250 (MCG加载/解码)
              └─ 0x10001B10 (MCG数据处理)
                  └─ 检查 "MCG 1.01" 签名
                  └─ 调用 vtable[0x160] 获取密钥
                  └─ call 0x10004789 ★ 核心解密+解压函数
```

### 4.3 密钥确认方法

由于密钥只有1字节(0-255)，且解密+LZSS解压后大小必须精确等于头部声明的raw_size，
可以通过暴力遍历在秒级内确认：

```python
for seed in range(256):
    decrypt(data, seed, count)
    result = lzss_decompress(data, raw_size)
    if len(result) == raw_size:  # 精确匹配
        print(f"Key found: 0x{seed:02X}")
```

## 5. 逆向方法论总结

### 5.1 x86 loop指令的寄存器复用陷阱

`loop` 指令隐式递减ECX。如果循环体内同时读取CL/CX/ECX作为参数，
该参数实际上是变化的。这种汇编层面的副作用在反编译伪代码中几乎不可见。

**发现手段：** Unicorn精确模拟原始机器码，逐字节对比Python翻译的输出，
在第3字节即发现差异，从而定位到cl不固定的根因。

### 5.2 模块化引擎的定位策略

对于DLL插件式架构：
1. 从exe的`LoadLibrary`/`GetProcAddress`追踪第一级DLL
2. 在DLL中搜索目标格式的magic字符串或特征常量
3. 通过导入表/字符串定位次级DLL加载
4. 在功能DLL中通过导出函数+dispatch表定位具体功能

### 5.3 已知明文攻击

MRG的GuessKey利用了文件末尾偏移这一已知明文，从最后4字节反推密钥。
MCG的暴力搜索利用了LZSS解压后大小的精确匹配作为校验条件。
两者都不需要硬编码密钥表。

---

## 6. 工具

| 工具 | 用途 | 关键参数 |
|------|------|----------|
| `mcg2png.py` | MCG图像→PNG | `-k 0x7B` (默认), `--bruteforce` |
| `mrg_unpack.py` | MRG封包解包 | `-l` 列表, `-b` 批量 |

MRG密钥自动推导，无需手动指定。MCG密钥默认0x7B（木漏れ日の並木道），
其他ADVWIN32游戏可用`--bruteforce`自动搜索。
