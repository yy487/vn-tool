/*
 * oni_dump.c - ONI Engine (鬼ノ棲ム桜) 运行时资源Dump工具
 *
 * 原理：通过DLL注入hook关键函数，在游戏运行时自动dump所有被加载的资源。
 *
 * Hook 策略：
 *   1. Hook CreateFileA → 记录打开的文件名
 *   2. Hook FUN_0040C1E0 (image_load) → 在函数返回后，从全局缓冲区dump解码后的图像
 *
 * 使用方法：
 *   方法A (DLL劫持): 用AheadLib生成winmm.dll转发，加载此DLL
 *   方法B (导入表注入): 用CFF Explorer或setdll.exe将此DLL加入EXE导入表
 *   方法C (启动器): 用DetourCreateProcessWithDllW启动游戏并注入
 *
 * 编译 (MSVC):
 *   cl /LD /O2 oni_dump.c /link user32.lib gdi32.lib kernel32.lib
 *
 * 编译 (MinGW):
 *   gcc -shared -o oni_dump.dll oni_dump.c -luser32 -lgdi32 -lkernel32 -O2
 *
 * 输出目录: 游戏目录下 _dump/ 文件夹
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ================================================================
 * 游戏内存地址 (来自逆向分析)
 * ================================================================ */

/* 全局缓冲区地址 */
#define ADDR_BITMAPINFO     0x00BB7300  /* BITMAPINFOHEADER (0x28 bytes) */
#define ADDR_EXTRA_HDR      0x00B929A0  /* Extra header (0x24 bytes) */
#define ADDR_PIXEL_BUF1     0x00429B50  /* 主像素缓冲区 (渲染用) */
#define ADDR_PIXEL_BUF2     0x0082FC5C  /* 临时像素缓冲区 */
#define ADDR_COMPRESS_BUF   0x00646678  /* 压缩数据缓冲区 */

/* 图像加载函数地址 */
#define ADDR_IMAGE_LOAD     0x0040C1E0  /* FUN_0040C1E0(mode, basename) */

/* ================================================================
 * Trampoline / Inline Hook 基础设施
 * ================================================================ */

/* 5字节 JMP rel32 hook */
#pragma pack(push, 1)
typedef struct {
    BYTE  opcode;      /* 0xE9 = JMP rel32 */
    DWORD rel_offset;
} JMP_PATCH;
#pragma pack(pop)

/* 保存原始字节用于调用原函数 */
static BYTE  g_origImageLoad[16];   /* FUN_0040C1E0 的原始前几字节 */
static BOOL  g_imageLoadHooked = FALSE;

/* 原始 CreateFileA 函数指针 (IAT hook) */
typedef HANDLE (WINAPI *PFN_CreateFileA)(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

static PFN_CreateFileA g_origCreateFileA = NULL;

/* 图像加载函数原型 */
typedef DWORD (__cdecl *PFN_ImageLoad)(DWORD mode, const char *basename);

/* ================================================================
 * Dump 输出
 * ================================================================ */

static char g_dumpDir[MAX_PATH] = "_dump";
static FILE *g_logFile = NULL;
static int g_dumpCount = 0;

/* 最近一次 CreateFileA 打开的文件名 */
static char g_lastOpenedFile[MAX_PATH] = {0};
static CRITICAL_SECTION g_cs;

static void EnsureDumpDir(void)
{
    CreateDirectoryA(g_dumpDir, NULL);
    
    char subdir[MAX_PATH];
    snprintf(subdir, sizeof(subdir), "%s\\images", g_dumpDir);
    CreateDirectoryA(subdir, NULL);
    
    snprintf(subdir, sizeof(subdir), "%s\\raw", g_dumpDir);
    CreateDirectoryA(subdir, NULL);
}

static void Log(const char *fmt, ...)
{
    if (!g_logFile) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);
    fflush(g_logFile);
}

/* 保存像素数据为BMP文件 */
static BOOL SaveBMP(const char *path, int width, int height, int bpp, 
                    const BYTE *pixels)
{
    int stride = ((width * (bpp / 8) + 3) & ~3);
    int dataSize = stride * height;
    int fileSize = 54 + dataSize;
    
    FILE *f = fopen(path, "wb");
    if (!f) return FALSE;
    
    /* BMP file header (14 bytes) */
    BYTE bmpFileHdr[14] = {0};
    bmpFileHdr[0] = 'B'; bmpFileHdr[1] = 'M';
    *(DWORD*)(bmpFileHdr + 2) = fileSize;
    *(DWORD*)(bmpFileHdr + 10) = 54;
    fwrite(bmpFileHdr, 1, 14, f);
    
    /* BITMAPINFOHEADER (40 bytes) */
    BYTE bmpInfoHdr[40] = {0};
    *(DWORD*)(bmpInfoHdr + 0)  = 40;
    *(LONG*)(bmpInfoHdr + 4)   = width;
    *(LONG*)(bmpInfoHdr + 8)   = height;  /* positive = bottom-up (正确) */
    *(WORD*)(bmpInfoHdr + 12)  = 1;
    *(WORD*)(bmpInfoHdr + 14)  = (WORD)bpp;
    *(DWORD*)(bmpInfoHdr + 20) = dataSize;
    fwrite(bmpInfoHdr, 1, 40, f);
    
    /* 像素数据 - 已经是 BGR bottom-up */
    int srcStride = width * (bpp / 8);
    for (int y = 0; y < height; y++) {
        fwrite(pixels + y * srcStride, 1, srcStride, f);
        /* 补齐stride对齐 */
        int pad = stride - srcStride;
        if (pad > 0) {
            BYTE zeros[4] = {0};
            fwrite(zeros, 1, pad, f);
        }
    }
    
    fclose(f);
    return TRUE;
}

/* ================================================================
 * Hook: CreateFileA (IAT Hook)
 * 目的：记录游戏打开的每个文件名
 * ================================================================ */

static HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    /* 记录文件名 */
    if (lpFileName) {
        EnterCriticalSection(&g_cs);
        strncpy(g_lastOpenedFile, lpFileName, MAX_PATH - 1);
        g_lastOpenedFile[MAX_PATH - 1] = '\0';
        LeaveCriticalSection(&g_cs);
        
        Log("[CreateFileA] %s\n", lpFileName);
    }
    
    return g_origCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                             lpSA, dwCreationDisposition,
                             dwFlagsAndAttributes, hTemplateFile);
}

/* ================================================================
 * Hook: FUN_0040C1E0 (Inline Hook / Trampoline)
 * 目的：在图像加载完成后，从全局缓冲区dump解码后的像素
 * ================================================================ */

/* 调用原始函数的 trampoline */
static DWORD CallOrigImageLoad(DWORD mode, const char *basename)
{
    /* 临时恢复原始字节 */
    DWORD oldProtect;
    VirtualProtect((LPVOID)ADDR_IMAGE_LOAD, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)ADDR_IMAGE_LOAD, g_origImageLoad, 16);
    VirtualProtect((LPVOID)ADDR_IMAGE_LOAD, 16, oldProtect, &oldProtect);
    
    /* 调用原始函数 */
    PFN_ImageLoad origFunc = (PFN_ImageLoad)ADDR_IMAGE_LOAD;
    DWORD result = origFunc(mode, basename);
    
    /* 重新安装hook */
    VirtualProtect((LPVOID)ADDR_IMAGE_LOAD, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    JMP_PATCH patch;
    patch.opcode = 0xE9;
    patch.rel_offset = (DWORD)&HookedImageLoad - (ADDR_IMAGE_LOAD + 5);
    memcpy((void*)ADDR_IMAGE_LOAD, &patch, 5);
    VirtualProtect((LPVOID)ADDR_IMAGE_LOAD, 5, oldProtect, &oldProtect);
    
    return result;
}

/* Hook函数 */
static DWORD __cdecl HookedImageLoad(DWORD mode, const char *basename)
{
    Log("[ImageLoad] mode=%d basename=\"%s\"\n", mode, basename ? basename : "(null)");
    
    /* 调用原始函数完成实际加载 */
    DWORD result = CallOrigImageLoad(mode, basename);
    
    if (result == 0) {
        Log("  → 加载失败\n");
        return result;
    }
    
    /* 从全局缓冲区读取 BITMAPINFOHEADER */
    BITMAPINFOHEADER *bih = (BITMAPINFOHEADER*)ADDR_BITMAPINFO;
    int width  = bih->biWidth;
    int height = bih->biHeight;
    int bpp    = bih->biBitCount;
    
    if (width <= 0 || height <= 0 || width > 4096 || height > 4096) {
        Log("  → 异常尺寸 %dx%d, 跳过\n", width, height);
        return result;
    }
    
    Log("  → 成功: %dx%d %dbpp\n", width, height, bpp);
    
    /* 确定像素数据源
     * 24bpp: 数据在 PIXEL_BUF1 (0x429B50) - 最终渲染缓冲区
     * 16bpp: 引擎会转换到 PIXEL_BUF1，bpp字段可能已被更新
     * 
     * 实际上引擎在0x40C4DE处有bpp判断：
     *   < 0x18 (24): 做16→24转换后写入PIXEL_BUF1，并设 biBitCount=0x10 (16)
     *   >= 0x18: 直接拷贝到PIXEL_BUF1，设 biBitCount=0x18 (24)
     *
     * 但在某些分支，数据可能在 PIXEL_BUF2 (0x82FC5C)
     * 安全起见：始终从 PIXEL_BUF1 读取（这是SetDIBitsToDevice的源）
     */
    
    /* dump使用的bpp: 引擎可能修改了bih->biBitCount */
    int dumpBpp = bih->biBitCount;
    if (dumpBpp != 24 && dumpBpp != 16) {
        /* 回退到24bpp */
        dumpBpp = 24;
    }
    
    int pixelSize = width * height * (dumpBpp / 8);
    BYTE *pixels = (BYTE*)ADDR_PIXEL_BUF1;
    
    /* 构建输出文件名 */
    char outpath[MAX_PATH];
    g_dumpCount++;
    
    if (basename && basename[0]) {
        snprintf(outpath, sizeof(outpath), "%s\\images\\%04d_%s.bmp", 
                 g_dumpDir, g_dumpCount, basename);
    } else {
        snprintf(outpath, sizeof(outpath), "%s\\images\\%04d_unknown.bmp",
                 g_dumpDir, g_dumpCount);
    }
    
    /* 保存为BMP */
    if (SaveBMP(outpath, width, height, dumpBpp, pixels)) {
        Log("  → DUMP: %s (%d bytes)\n", outpath, pixelSize);
    } else {
        Log("  → DUMP失败: %s\n", outpath);
    }
    
    return result;
}

/* ================================================================
 * IAT Hook 安装 (修改导入地址表)
 * ================================================================ */

static BOOL InstallIATHook(HMODULE hModule, const char *dllName, 
                           const char *funcName, void *hookFunc, void **origFunc)
{
    /* 获取PE头 */
    BYTE *base = (BYTE*)hModule;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    
    /* 获取导入描述符 */
    DWORD importRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) return FALSE;
    
    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(base + importRVA);
    
    while (importDesc->Name) {
        char *name = (char*)(base + importDesc->Name);
        if (_stricmp(name, dllName) == 0) {
            /* 找到目标DLL的导入表 */
            IMAGE_THUNK_DATA *origThunk = (IMAGE_THUNK_DATA*)(base + importDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA *firstThunk = (IMAGE_THUNK_DATA*)(base + importDesc->FirstThunk);
            
            while (origThunk->u1.AddressOfData) {
                if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    IMAGE_IMPORT_BY_NAME *import = 
                        (IMAGE_IMPORT_BY_NAME*)(base + origThunk->u1.AddressOfData);
                    
                    if (strcmp(import->Name, funcName) == 0) {
                        /* 找到目标函数，修改IAT */
                        DWORD oldProtect;
                        VirtualProtect(&firstThunk->u1.Function, sizeof(DWORD_PTR),
                                      PAGE_READWRITE, &oldProtect);
                        
                        *origFunc = (void*)(DWORD_PTR)firstThunk->u1.Function;
                        firstThunk->u1.Function = (DWORD_PTR)hookFunc;
                        
                        VirtualProtect(&firstThunk->u1.Function, sizeof(DWORD_PTR),
                                      oldProtect, &oldProtect);
                        return TRUE;
                    }
                }
                origThunk++;
                firstThunk++;
            }
        }
        importDesc++;
    }
    return FALSE;
}

/* ================================================================
 * Inline Hook 安装 (修改函数入口的前5字节为 JMP)
 * ================================================================ */

static BOOL InstallInlineHook(DWORD targetAddr, void *hookFunc, 
                               BYTE *origBytes, int saveCount)
{
    DWORD oldProtect;
    
    /* 保存原始字节 */
    if (!VirtualProtect((LPVOID)targetAddr, saveCount, 
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    memcpy(origBytes, (void*)targetAddr, saveCount);
    
    /* 写入 JMP rel32 */
    JMP_PATCH patch;
    patch.opcode = 0xE9;
    patch.rel_offset = (DWORD)hookFunc - (targetAddr + 5);
    memcpy((void*)targetAddr, &patch, 5);
    
    VirtualProtect((LPVOID)targetAddr, saveCount, oldProtect, &oldProtect);
    return TRUE;
}

/* ================================================================
 * DLL 入口
 * ================================================================ */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);
        
        /* 创建输出目录 */
        EnsureDumpDir();
        
        /* 打开日志 */
        char logpath[MAX_PATH];
        snprintf(logpath, sizeof(logpath), "%s\\dump_log.txt", g_dumpDir);
        g_logFile = fopen(logpath, "w");
        Log("=== ONI Engine Resource Dumper ===\n");
        Log("Game: 鬼ノ棲ム桜\n");
        Log("Hook targets:\n");
        Log("  CreateFileA (IAT) → 记录文件访问\n");
        Log("  0x%08X (inline) → dump解码后图像\n\n", ADDR_IMAGE_LOAD);
        
        /* 安装 IAT Hook: CreateFileA */
        HMODULE hExe = GetModuleHandleA(NULL);
        if (InstallIATHook(hExe, "kernel32.dll", "CreateFileA",
                          (void*)HookedCreateFileA, (void**)&g_origCreateFileA)) {
            Log("[+] CreateFileA IAT hook installed\n");
        } else {
            Log("[-] CreateFileA IAT hook FAILED\n");
            /* 回退: 直接获取原始函数地址 */
            g_origCreateFileA = (PFN_CreateFileA)GetProcAddress(
                GetModuleHandleA("kernel32.dll"), "CreateFileA");
        }
        
        /* 安装 Inline Hook: FUN_0040C1E0 (图像加载) */
        if (InstallInlineHook(ADDR_IMAGE_LOAD, (void*)HookedImageLoad,
                             g_origImageLoad, 16)) {
            g_imageLoadHooked = TRUE;
            Log("[+] ImageLoad inline hook installed at 0x%08X\n", ADDR_IMAGE_LOAD);
        } else {
            Log("[-] ImageLoad inline hook FAILED\n");
        }
        
        Log("\n=== Hooks ready, waiting for game to load resources... ===\n\n");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        /* 恢复 inline hook */
        if (g_imageLoadHooked) {
            DWORD oldProtect;
            VirtualProtect((LPVOID)ADDR_IMAGE_LOAD, 16, 
                          PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((void*)ADDR_IMAGE_LOAD, g_origImageLoad, 16);
            VirtualProtect((LPVOID)ADDR_IMAGE_LOAD, 16, oldProtect, &oldProtect);
        }
        
        if (g_logFile) {
            Log("\n=== Dumper detached. Total images dumped: %d ===\n", g_dumpCount);
            fclose(g_logFile);
        }
        DeleteCriticalSection(&g_cs);
    }
    
    return TRUE;
}

/* 导出函数 (用于导入表注入时需要至少一个导出) */
__declspec(dllexport) void OniDumpInit(void) 
{
    /* 空函数，仅用于导入表注入 */
}
