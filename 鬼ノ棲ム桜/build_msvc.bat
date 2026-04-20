@echo off
REM ═══════════════════════════════════════════════
REM  ONI Engine Resource Dumper - 编译脚本
REM  
REM  使用前请先打开 "Developer Command Prompt for VS"
REM  或 "x86 Native Tools Command Prompt"
REM  然后在该命令行中运行此脚本
REM ═══════════════════════════════════════════════

echo.
echo  编译 ONI Engine Resource Dumper (winmm.dll)
echo  ============================================
echo.

REM 检查cl.exe是否可用
where cl >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [错误] 未找到 cl.exe
    echo.
    echo  请使用以下方式之一打开命令行:
    echo    - 开始菜单 ^> Visual Studio ^> Developer Command Prompt
    echo    - 开始菜单 ^> Visual Studio ^> x86 Native Tools Command Prompt  
    echo.
    echo  然后重新运行此脚本。
    pause
    exit /b 1
)

echo  [1/2] 编译中...
cl /LD /O2 /W3 oni_winmm.c /Fe:winmm.dll /link user32.lib kernel32.lib winmm.lib /DEF:NUL

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [错误] 编译失败！
    pause
    exit /b 1
)

echo.
echo  [2/2] 清理临时文件...
del /q oni_winmm.obj 2>nul
del /q winmm.exp 2>nul
del /q winmm.lib 2>nul

echo.
echo  ============================================
echo  编译成功！生成文件: winmm.dll
echo  ============================================
echo.
echo  使用步骤:
echo    1. 复制 C:\Windows\System32\winmm.dll 到游戏目录
echo       改名为 winmm_orig.dll
echo    2. 把编译出的 winmm.dll 放到游戏目录
echo    3. 正常启动 ONI.exe
echo    4. dump结果在 _dump\images\ 目录
echo.
pause
