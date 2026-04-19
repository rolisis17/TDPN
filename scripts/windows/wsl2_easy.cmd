@echo off
setlocal

set "SCRIPT_DIR=%~dp0"

if /I "%~1"=="bootstrap" (
  shift
  if not "%~1"=="" (
    echo This wrapper does not accept arguments.
    echo Use "%SCRIPT_DIR%wsl2_bootstrap.ps1" directly for PowerShell arguments.
    endlocal & exit /b 1
  )
  call "%SCRIPT_DIR%wsl2_bootstrap.cmd"
  endlocal & exit /b %ERRORLEVEL%
)

if /I "%~1"=="run" (
  shift
  if not "%~1"=="" (
    echo This wrapper does not accept arguments.
    echo Use "%SCRIPT_DIR%wsl2_run_easy.ps1" directly for PowerShell arguments.
    endlocal & exit /b 1
  )
  call "%SCRIPT_DIR%wsl2_run_easy.cmd"
  endlocal & exit /b %ERRORLEVEL%
)

echo Usage:
echo   wsl2_easy.cmd bootstrap
echo   wsl2_easy.cmd run
echo.
echo Examples:
echo   wsl2_easy.cmd bootstrap
echo   wsl2_easy.cmd run
echo.
echo For PowerShell arguments, call:
echo   wsl2_bootstrap.ps1
echo   wsl2_run_easy.ps1

endlocal & exit /b 0
