@echo off
REM ═══════════════════════════════════════════════
REM  ONI Engine Resource Dumper - MinGW 编译脚本
REM ═══════════════════════════════════════════════

echo.
echo  编译 ONI Engine Resource Dumper (winmm.dll) - MinGW
echo  ====================================================
echo.

where gcc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [错误] 未找到 gcc
    echo  请确保 MinGW 的 bin 目录在 PATH 中
    echo  例如: set PATH=C:\mingw32\bin;%%PATH%%
    pause
    exit /b 1
)

echo  编译中...
gcc -shared -o winmm.dll oni_winmm.c -lwinmm -luser32 -lkernel32 -O2 -m32 -Wl,--enable-stdcall-fixup

if %ERRORLEVEL% NEQ 0 (
    echo  [错误] 编译失败！
    pause
    exit /b 1
)

echo.
echo  编译成功！生成文件: winmm.dll
echo.
echo  使用步骤:
echo    1. 复制 C:\Windows\System32\winmm.dll 到游戏目录，改名 winmm_orig.dll
echo    2. 把编译出的 winmm.dll 放到游戏目录
echo    3. 正常启动 ONI.exe
echo    4. dump结果在 _dump\images\ 目录
echo.
pause
