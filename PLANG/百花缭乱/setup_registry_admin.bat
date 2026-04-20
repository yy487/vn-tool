@echo off
rem ============================================================
rem  Hyakka Ryouran (Nihon Plantech) Registry Setup
rem  Right-click this bat -> Run as administrator
rem  Output is also written to setup_log.txt (same folder)
rem ============================================================

cd /d "%~dp0"
set LOG=%~dp0setup_log.txt

echo =============================================== > "%LOG%"
echo Run at %date% %time% >> "%LOG%"
echo Working dir: %cd% >> "%LOG%"
echo =============================================== >> "%LOG%"

echo.
echo Working dir: %cd%
echo Log file   : %LOG%
echo.

rem --- Admin check at bat level -------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] NOT running as administrator.
    echo         Right-click this bat and choose "Run as administrator".
    echo [ERROR] NOT running as administrator. >> "%LOG%"
    echo.
    echo Press any key to close...
    pause >nul
    exit /b 1
)
echo [OK] Running as administrator.
echo.

rem --- PowerShell does the registry work, output tee'd to log --
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try {" ^
  "  $ErrorActionPreference='Stop';" ^
  "  $g=(Get-Location).Path;" ^
  "  if (-not $g.EndsWith('\')) { $g = $g + '\' };" ^
  "  $sub='SOFTWARE\' + [char]0x65E5 + [char]0x672C + [char]0x30D7 + [char]0x30E9 + [char]0x30F3 + [char]0x30C6 + [char]0x30C3 + [char]0x30AF + '\' + [char]0x767E + [char]0x82B1 + [char]0x7E5A + [char]0x4E71 + '\1.0\PLANTECH APPLICATION';" ^
  "  Write-Host ('Game path : ' + $g);" ^
  "  Write-Host ('Subkey    : HKLM\' + $sub);" ^
  "  Write-Host '';" ^
  "  function Write-Reg($view, $label) {" ^
  "    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine',$view);" ^
  "    $k=$base.CreateSubKey($sub);" ^
  "    if ($k -eq $null) { throw ('CreateSubKey failed for ' + $label) };" ^
  "    $k.SetValue('MainPath',  $g,             'String');" ^
  "    $k.SetValue('SinPath',   $g + 'SIN\',    'String');" ^
  "    $k.SetValue('MessPath',  $g + 'MESS\',   'String');" ^
  "    $k.SetValue('AnimPath', $g + 'ANIM\',    'String');" ^
  "    $k.SetValue('MidiPath',  $g + 'MIDI\',   'String');" ^
  "    $k.SetValue('WavPath',   $g + 'WAV\',    'String');" ^
  "    $k.SetValue('VoicePath', $g + 'VOICE\',  'String');" ^
  "    $k.SetValue('PacPath',   $g + 'PAC\',    'String');" ^
  "    $k.SetValue('SetupType', '2',            'String');" ^
  "    $k.Close();" ^
  "    Write-Host ('[OK] wrote ' + $label)" ^
  "  };" ^
  "  Write-Reg 'Registry32' '32-bit view (WOW6432Node)';" ^
  "  Write-Reg 'Registry64' '64-bit view';" ^
  "  Write-Host '';" ^
  "  Write-Host '--- Verify 32-bit view ---';" ^
  "  $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry32');" ^
  "  $k2=$base.OpenSubKey($sub);" ^
  "  if ($k2 -eq $null) { throw 'Verify failed: cannot open key after write' };" ^
  "  foreach ($n in 'MainPath','SinPath','MessPath','AnimPath','MidiPath','WavPath','VoicePath','PacPath','SetupType') {" ^
  "    $v=$k2.GetValue($n);" ^
  "    if ($v -eq $null) { Write-Host ('  ' + $n.PadRight(11) + '= <MISSING>') }" ^
  "    else { Write-Host ('  ' + $n.PadRight(11) + '= ' + $v) }" ^
  "  };" ^
  "  $k2.Close();" ^
  "  Write-Host '';" ^
  "  Write-Host '[DONE] Registry setup finished successfully.'" ^
  "} catch {" ^
  "  Write-Host '';" ^
  "  Write-Host ('[EXCEPTION] ' + $_.Exception.Message) -Foreground Red;" ^
  "  Write-Host ($_.ScriptStackTrace) -Foreground DarkGray;" ^
  "  exit 1" ^
  "}" >> "%LOG%" 2>&1

rem --- Show log to the console so user sees it ----------------
type "%LOG%"

echo.
echo ------------------------------------------------------------
echo Log saved to: %LOG%
echo ------------------------------------------------------------
echo.
echo Press any key to close...
pause >nul
