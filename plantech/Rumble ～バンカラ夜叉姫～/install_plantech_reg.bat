@echo off
chcp 932 >nul 2>&1
setlocal

rem ============================================================
rem  PLANTECH (Rumble) 注册表自动配置脚本
rem  把本 bat 放到游戏根目录 (PLANTECH.exe 所在文件夹), 双击运行.
rem  会按当前路径写入 HKLM 注册表项, 之后游戏即可启动.
rem  需要管理员权限.
rem ============================================================

rem 取当前 bat 所在目录 (末尾带反斜杠)
set "GAME=%~dp0"

rem 把单反斜杠变成双反斜杠 (.reg 文件要求)
set "G=%GAME:\=\\%"

rem 生成临时 .reg 文件
set "TMPREG=%TEMP%\plantech_setup.reg"

> "%TMPREG%" echo Windows Registry Editor Version 5.00
>>"%TMPREG%" echo.
>>"%TMPREG%" echo [HKEY_LOCAL_MACHINE\SOFTWARE\ペンギンワークス\Ｒｕｍｂｌｅ\1.0\PLANTECH APPLICATION]
>>"%TMPREG%" echo "MainPath"="%G%"
>>"%TMPREG%" echo "SinPath"="%G%SIN\\"
>>"%TMPREG%" echo "MessPath"="%G%MESS\\"
>>"%TMPREG%" echo "AnimPath"="%G%ANIM\\"
>>"%TMPREG%" echo "MidiPath"="%G%MIDI\\"
>>"%TMPREG%" echo "WavPath"="%G%WAV\\"
>>"%TMPREG%" echo "VoicePath"="%G%VOICE\\"
>>"%TMPREG%" echo "PacPath"="%G%PAC\\"
>>"%TMPREG%" echo "SetupType"="2"

rem 导入注册表 (静默, 需管理员)
regedit /s "%TMPREG%"
if %errorlevel% neq 0 (
    echo.
    echo [错误] 注册表导入失败. 请右键以管理员身份运行本 bat.
    echo.
    pause
    exit /b 1
)

del "%TMPREG%" >nul 2>&1

echo.
echo [OK] 注册表已配置完成
echo      游戏路径: %GAME%
echo      现在可以启动 PLANTECH.exe
echo.
pause
