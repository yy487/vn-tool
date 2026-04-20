/*
 * oni_winmm.c - ONI Engine (鬼ノ棲ム桜) 资源Dump工具
 * 
 * 通过劫持 winmm.dll 注入游戏进程，hook 图像加载函数
 * 在游戏运行时自动dump所有解码后的图像资源为BMP文件
 *
 * ═══════════════════════════════════════════════
 *  编译 (选择一种):
 * ═══════════════════════════════════════════════
 *
 *  【MSVC (推荐)】
 *    cl /LD /O2 oni_winmm.c /Fe:winmm.dll /link user32.lib kernel32.lib winmm.lib
 *
 *  【MinGW】
 *    gcc -shared -o winmm.dll oni_winmm.c -lwinmm -luser32 -lkernel32 -O2 -Wl,--enable-stdcall-fixup
 *
 * ═══════════════════════════════════════════════
 *  使用方法:
 * ═══════════════════════════════════════════════
 *
 *  1. 编译得到 winmm.dll
 *  2. 把系统目录 C:\Windows\System32\winmm.dll 复制到游戏目录，改名为 winmm_orig.dll
 *  3. 把编译出的 winmm.dll 放到游戏目录
 *  4. 正常启动游戏
 *  5. 游戏过程中加载的所有图像会自动保存到 _dump\images\ 目录
 *  6. 查看 _dump\dump_log.txt 获取详细日志
 *
 *  卸载：删除游戏目录下的 winmm.dll，把 winmm_orig.dll 改回 winmm.dll（或直接删除）
 *
 * ═══════════════════════════════════════════════
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ================================================================
 * Part 1: winmm.dll 转发
 * 
 * 游戏只用了3个winmm函数，我们把它们转发到原始DLL
 * ================================================================ */

static HMODULE g_hOrigWinmm = NULL;

/* 原始函数指针 */
typedef DWORD  (WINAPI *PFN_mciSendCommandA)(UINT, UINT, DWORD_PTR, DWORD_PTR);
typedef BOOL   (WINAPI *PFN_PlaySoundA)(LPCSTR, HMODULE, DWORD);
typedef DWORD  (WINAPI *PFN_timeGetTime)(void);

static PFN_mciSendCommandA pfn_mciSendCommandA = NULL;
static PFN_PlaySoundA      pfn_PlaySoundA      = NULL;
static PFN_timeGetTime     pfn_timeGetTime     = NULL;

/* 转发导出函数 */
__declspec(dllexport) DWORD WINAPI mciSendCommandA(UINT a, UINT b, DWORD_PTR c, DWORD_PTR d)
{
    if (pfn_mciSendCommandA)
        return pfn_mciSendCommandA(a, b, c, d);
    return 0;
}

__declspec(dllexport) BOOL WINAPI PlaySoundA(LPCSTR a, HMODULE b, DWORD c)
{
    if (pfn_PlaySoundA)
        return pfn_PlaySoundA(a, b, c);
    return FALSE;
}

__declspec(dllexport) DWORD WINAPI timeGetTime(void)
{
    if (pfn_timeGetTime)
        return pfn_timeGetTime();
    return 0;
}

static BOOL LoadOriginalWinmm(void)
{
    /* 先尝试游戏目录下的 winmm_orig.dll */
    g_hOrigWinmm = LoadLibraryA("winmm_orig.dll");
    
    if (!g_hOrigWinmm) {
        /* 回退到系统目录 */
        char sysdir[MAX_PATH];
        GetSystemDirectoryA(sysdir, MAX_PATH);
        strcat(sysdir, "\\winmm.dll");
        g_hOrigWinmm = LoadLibraryA(sysdir);
    }
    
    if (!g_hOrigWinmm)
        return FALSE;
    
    pfn_mciSendCommandA = (PFN_mciSendCommandA)GetProcAddress(g_hOrigWinmm, "mciSendCommandA");
    pfn_PlaySoundA      = (PFN_PlaySoundA)GetProcAddress(g_hOrigWinmm, "PlaySoundA");
    pfn_timeGetTime     = (PFN_timeGetTime)GetProcAddress(g_hOrigWinmm, "timeGetTime");
    
    return TRUE;
}

/* ================================================================
 * Part 2: 资源 Dump 核心逻辑
 * ================================================================ */

/* 游戏内存地址 (硬编码，仅适用于本游戏特定版本) */
#define ADDR_BITMAPINFO   0x00BB7300  /* BITMAPINFOHEADER 全局缓冲区 */
#define ADDR_PIXEL_BUF    0x00429B50  /* 主像素缓冲区 (SetDIBitsToDevice源) */
#define ADDR_IMAGE_LOAD   0x0040C1E0  /* 图像加载函数入口 */

static FILE *g_logFile = NULL;
static int   g_dumpCount = 0;
static BYTE  g_origBytes[16];        /* 保存原始函数入口字节 */
static BOOL  g_hooked = FALSE;

static void Log(const char *fmt, ...)
{
    if (!g_logFile) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);
    fflush(g_logFile);
}

/* 保存像素为BMP */
static BOOL SaveBMP(const char *path, int width, int height, int bpp, const BYTE *pixels)
{
    int bytesPerPix = bpp / 8;
    int srcStride = width * bytesPerPix;
    int dstStride = (srcStride + 3) & ~3;  /* 4字节对齐 */
    int dataSize = dstStride * height;
    
    FILE *f = fopen(path, "wb");
    if (!f) return FALSE;
    
    /* BMP File Header (14 bytes) */
    BYTE fhdr[14] = {'B','M', 0,0,0,0, 0,0,0,0, 54,0,0,0};
    *(DWORD*)(fhdr+2) = 54 + dataSize;
    fwrite(fhdr, 1, 14, f);
    
    /* BITMAPINFOHEADER (40 bytes) */
    BYTE ihdr[40] = {0};
    *(DWORD*)(ihdr+0)  = 40;
    *(LONG*)(ihdr+4)   = width;
    *(LONG*)(ihdr+8)   = height;    /* positive = bottom-up */
    *(WORD*)(ihdr+12)  = 1;         /* planes */
    *(WORD*)(ihdr+14)  = (WORD)bpp;
    *(DWORD*)(ihdr+20) = dataSize;
    fwrite(ihdr, 1, 40, f);
    
    /* Pixel data */
    BYTE pad[4] = {0};
    int padSize = dstStride - srcStride;
    for (int y = 0; y < height; y++) {
        fwrite(pixels + y * srcStride, 1, srcStride, f);
        if (padSize > 0)
            fwrite(pad, 1, padSize, f);
    }
    
    fclose(f);
    return TRUE;
}

/* ================================================================
 * Part 3: Inline Hook
 *
 * 原理: 把 FUN_0040C1E0 的前5字节改为 JMP 到我们的函数
 * 调用原函数时: 临时恢复原字节 → call → 重装hook
 * ================================================================ */

/* 游戏的图像加载函数原型: int __cdecl FUN_0040C1E0(int mode, char *basename) */
typedef int (__cdecl *PFN_ImageLoad)(int mode, const char *basename);

/* 前向声明 */
static int __cdecl HookedImageLoad(int mode, const char *basename);

static int CallOrigImageLoad(int mode, const char *basename)
{
    DWORD old;
    
    /* 恢复原始字节 */
    VirtualProtect((void*)ADDR_IMAGE_LOAD, 16, PAGE_EXECUTE_READWRITE, &old);
    memcpy((void*)ADDR_IMAGE_LOAD, g_origBytes, 16);
    VirtualProtect((void*)ADDR_IMAGE_LOAD, 16, old, &old);
    
    /* 调用原函数 */
    PFN_ImageLoad fn = (PFN_ImageLoad)ADDR_IMAGE_LOAD;
    int ret = fn(mode, basename);
    
    /* 重装hook */
    VirtualProtect((void*)ADDR_IMAGE_LOAD, 5, PAGE_EXECUTE_READWRITE, &old);
    BYTE jmp[5];
    jmp[0] = 0xE9;
    *(DWORD*)(jmp+1) = (DWORD)&HookedImageLoad - (ADDR_IMAGE_LOAD + 5);
    memcpy((void*)ADDR_IMAGE_LOAD, jmp, 5);
    VirtualProtect((void*)ADDR_IMAGE_LOAD, 5, old, &old);
    
    return ret;
}

/* Hook 函数 */
static int __cdecl HookedImageLoad(int mode, const char *basename)
{
    const char *name = (basename && basename[0]) ? basename : "(null)";
    Log("[LOAD] mode=%d name=\"%s\"\n", mode, name);
    
    /* 调用原函数 */
    int ret = CallOrigImageLoad(mode, basename);
    
    if (ret == 0) {
        Log("  -> FAIL\n");
        return ret;
    }
    
    /* 从全局缓冲区读取图像信息 */
    typedef struct {
        DWORD biSize;
        LONG  biWidth;
        LONG  biHeight;
        WORD  biPlanes;
        WORD  biBitCount;
    } BMPINFOHDR_PARTIAL;
    
    BMPINFOHDR_PARTIAL *bih = (BMPINFOHDR_PARTIAL*)ADDR_BITMAPINFO;
    int w   = bih->biWidth;
    int h   = bih->biHeight;
    int bpp = bih->biBitCount;
    
    /* 健全性检查 */
    if (w <= 0 || h <= 0 || w > 4096 || h > 4096 || (bpp != 16 && bpp != 24)) {
        Log("  -> OK but skip dump (w=%d h=%d bpp=%d)\n", w, h, bpp);
        return ret;
    }
    
    /* 构建输出路径 */
    g_dumpCount++;
    char outpath[MAX_PATH];
    snprintf(outpath, MAX_PATH, "_dump\\images\\%04d_%s.bmp", g_dumpCount, name);
    
    /* Dump */
    BYTE *pixels = (BYTE*)ADDR_PIXEL_BUF;
    if (SaveBMP(outpath, w, h, bpp, pixels)) {
        Log("  -> DUMP %dx%d %dbpp -> %s\n", w, h, bpp, outpath);
    } else {
        Log("  -> dump FAILED: %s\n", outpath);
    }
    
    return ret;
}

static BOOL InstallHook(void)
{
    DWORD old;
    if (!VirtualProtect((void*)ADDR_IMAGE_LOAD, 16, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;
    
    /* 保存原始字节 */
    memcpy(g_origBytes, (void*)ADDR_IMAGE_LOAD, 16);
    
    /* 写入 JMP rel32 */
    BYTE jmp[5];
    jmp[0] = 0xE9;  /* JMP rel32 */
    *(DWORD*)(jmp+1) = (DWORD)&HookedImageLoad - (ADDR_IMAGE_LOAD + 5);
    memcpy((void*)ADDR_IMAGE_LOAD, jmp, 5);
    
    VirtualProtect((void*)ADDR_IMAGE_LOAD, 16, old, &old);
    return TRUE;
}

static void UninstallHook(void)
{
    if (!g_hooked) return;
    DWORD old;
    VirtualProtect((void*)ADDR_IMAGE_LOAD, 16, PAGE_EXECUTE_READWRITE, &old);
    memcpy((void*)ADDR_IMAGE_LOAD, g_origBytes, 16);
    VirtualProtect((void*)ADDR_IMAGE_LOAD, 16, old, &old);
}

/* ================================================================
 * Part 4: DLL 入口
 * ================================================================ */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        
        /* Step 1: 加载原始winmm.dll */
        if (!LoadOriginalWinmm()) {
            MessageBoxA(NULL, 
                "无法加载原始 winmm.dll!\n\n"
                "请确保 winmm_orig.dll 存在于游戏目录，\n"
                "或系统目录下有 winmm.dll。",
                "ONI Dump Error", MB_ICONERROR);
            return FALSE;
        }
        
        /* Step 2: 创建输出目录 */
        CreateDirectoryA("_dump", NULL);
        CreateDirectoryA("_dump\\images", NULL);
        
        /* Step 3: 打开日志 */
        g_logFile = fopen("_dump\\dump_log.txt", "w");
        Log("========================================\n");
        Log("  ONI Engine Resource Dumper\n");
        Log("  Game: 鬼ノ棲ム桜\n");
        Log("========================================\n\n");
        
        /* Step 4: 安装hook */
        if (InstallHook()) {
            g_hooked = TRUE;
            Log("[+] Hook installed at 0x%08X\n", ADDR_IMAGE_LOAD);
            Log("[*] Ready. Play the game normally.\n");
            Log("[*] Images will be saved to _dump\\images\\\n\n");
        } else {
            Log("[-] Hook FAILED! VirtualProtect error.\n");
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        UninstallHook();
        
        if (g_logFile) {
            Log("\n[*] Game exiting. Total dumps: %d\n", g_dumpCount);
            fclose(g_logFile);
        }
        
        if (g_hOrigWinmm)
            FreeLibrary(g_hOrigWinmm);
    }
    
    return TRUE;
}
