@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%desktop_release_bundle.ps1"

if not exist "%PS1%" (
  echo Missing PowerShell script: "%PS1%"
  endlocal & exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo.
  echo Desktop release bundle scaffold failed with exit code %EXIT_CODE%.
)

endlocal & exit /b %EXIT_CODE%
