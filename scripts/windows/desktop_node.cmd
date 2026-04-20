@echo off
setlocal DisableDelayedExpansion
set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%desktop_node.ps1"
if not exist "%PS1%" (
  echo missing script: %PS1%
  exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"
exit /b %RC%
