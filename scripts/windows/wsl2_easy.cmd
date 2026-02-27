@echo off
setlocal

set "SCRIPT_DIR=%~dp0"

if /I "%~1"=="bootstrap" (
  shift
  call "%SCRIPT_DIR%wsl2_bootstrap.cmd" %*
  endlocal & exit /b %ERRORLEVEL%
)

if /I "%~1"=="run" (
  shift
  call "%SCRIPT_DIR%wsl2_run_easy.cmd" %*
  endlocal & exit /b %ERRORLEVEL%
)

echo Usage:
echo   wsl2_easy.cmd bootstrap [PowerShell args...]
echo   wsl2_easy.cmd run [PowerShell args...]
echo.
echo Examples:
echo   wsl2_easy.cmd bootstrap
echo   wsl2_easy.cmd bootstrap -Distro Ubuntu-22.04
echo   wsl2_easy.cmd run
echo   wsl2_easy.cmd run -Distro Ubuntu-22.04

endlocal & exit /b 0
