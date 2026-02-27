@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%wsl2_run_easy.ps1"

if not exist "%PS1%" (
  echo Missing PowerShell script: "%PS1%"
  endlocal & exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo.
  echo WSL2 launcher failed with exit code %EXIT_CODE%.
)

endlocal & exit /b %EXIT_CODE%
